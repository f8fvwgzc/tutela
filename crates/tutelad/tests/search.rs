//! The search APIs through the real auth layer and a real Postgres.
#![cfg(test)]

mod common;

use std::collections::BTreeSet;

use common::{AGENT, B_USER, SA, STRANGER, Seed, USER, World, http, publish, world, world_with};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutelad::authz::grpc::pb;
use tutelad::authz::grpc::pb::authz_client::AuthzClient;

const RESOURCE: &str = "/access/v1/search/resource";
const SUBJECT: &str = "/access/v1/search/subject";
const EVAL: &str = "/access/v1/evaluation";

fn kind(p: &str) -> &str {
    p.split(':').next().unwrap()
}

fn by_subject(subject: &str, action: &str, ty: &str) -> Value {
    json!({
        "subject": {"type": kind(subject), "id": subject},
        "action": {"name": action},
        "resource": {"type": ty},
    })
}

fn who_may(kind: &str, action: &str, s: &Seed) -> Value {
    json!({
        "subject": {"type": kind},
        "action": {"name": action},
        "resource": {"type": "invoice", "id": "inv-1", "properties": {"path": common::path(s), "attrs": {}}},
    })
}

/// Registers an invoice under the project, as a product would, so that
/// Tutela can name it. Returns its id.
async fn invoice(w: &mut World, id: &str) {
    let World { d, a, .. } = w;
    let tx = d.owner.transaction().await.unwrap();
    let scope = tutela_pdp::PathEntry::new("invoice".parse().unwrap(), id.parse().unwrap());
    tutela_store::put_scope(
        &tx,
        &a.key,
        &scope,
        &[a.project.clone(), a.org.clone()],
        false,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn post(w: &World, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
    let r = w.post(path, token, body).await;
    let status = r.status();
    (status, r.json().await.unwrap_or(Value::Null))
}

fn ids(v: &Value) -> Vec<&str> {
    v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect()
}

/// A world where a change shows at once, for the tests that write.
async fn strict() -> Option<World> {
    world_with(|c| c.limits.check_every = std::time::Duration::ZERO).await
}

#[tokio::test]
async fn a_resource_search_names_what_check_allows_and_gives_the_filter() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    invoice(&mut w, "inv-2").await;
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (status, body) = post(
        &w,
        RESOURCE,
        &token,
        &by_subject(USER, "invoice:read", "invoice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), ["inv-1", "inv-2"]);
    assert_eq!(body["page"]["next_token"], "");
    assert_eq!(body["page"]["count"], 2);
    let filter = &body["context"]["tutela"]["filter"];
    assert_eq!(filter["type"], "invoice");
    assert_eq!(filter["container_in"][0]["id"], "p-1");
    assert_eq!(filter["rev"], body["context"]["tutela"]["rev"]);

    // Each one named agrees with `check`.
    for id in ids(&body) {
        let mut ask = common::ask(USER, "invoice:read", &w.a);
        ask["resource"]["id"] = json!(id);
        let (_, d) = post(&w, EVAL, &token, &ask).await;
        assert_eq!(d["decision"], true);
    }
    w.finish().await;
}

#[tokio::test]
async fn a_denied_principal_finds_nothing_and_has_no_filter_to_use() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    let token = w.issuer.token(SA, &w.a.tid, 0);
    for (subject, action) in [(STRANGER, "invoice:read"), (USER, "invoice:write")] {
        let (status, body) = post(
            &w,
            RESOURCE,
            &token,
            &by_subject(subject, action, "invoice"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(ids(&body).is_empty(), "{subject} {action}: {body}");
        let f = &body["context"]["tutela"]["filter"];
        assert_eq!(f["ids_in"], json!([]));
        assert_eq!(f["container_in"], json!([]));
    }
    w.finish().await;
}

/// The same project id exists in both tenants. Neither search sees the
/// other's, and a subject of the other tenant is just a subject with
/// nothing here.
#[tokio::test]
async fn tm05_neither_search_crosses_a_tenant() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    let a = w.issuer.token(SA, &w.a.tid, 0);
    let (s1, in_b) = post(
        &w,
        RESOURCE,
        &a,
        &by_subject(B_USER, "invoice:read", "invoice"),
    )
    .await;
    let (s2, nowhere) = post(
        &w,
        RESOURCE,
        &a,
        &by_subject(STRANGER, "invoice:read", "invoice"),
    )
    .await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(in_b, nowhere);

    let b = w.issuer.token(SA, &w.b.tid, 0);
    let (_, theirs) = post(
        &w,
        RESOURCE,
        &b,
        &by_subject(USER, "invoice:read", "invoice"),
    )
    .await;
    assert!(ids(&theirs).is_empty(), "{theirs}");

    // Who may read A's invoice, asked by B: no one that B can see, and A's
    // reader is not named.
    let (status, body) = post(&w, SUBJECT, &b, &who_may("user", "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["results"], json!([]));
    let (_, own) = post(&w, SUBJECT, &a, &who_may("user", "invoice:read", &w.a)).await;
    assert_eq!(ids(&own), [USER]);
    w.finish().await;
}

#[tokio::test]
async fn a_person_searches_its_own_access_and_cannot_list_anyone() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    let mine = w.issuer.token(USER, &w.a.tid, 0);
    let (status, body) = post(
        &w,
        RESOURCE,
        &mine,
        &by_subject(USER, "invoice:read", "invoice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body), ["inv-1"]);

    let (status, _) = post(
        &w,
        RESOURCE,
        &mine,
        &by_subject(STRANGER, "invoice:read", "invoice"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = post(&w, SUBJECT, &mine, &who_may("user", "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.get("results").is_none());

    let agent = w.issuer.token(AGENT, &w.a.tid, 0);
    let (status, _) = post(&w, SUBJECT, &agent, &who_may("user", "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    w.finish().await;
}

#[tokio::test]
async fn pages_are_bounded_and_cover_the_list_once() {
    let Some(mut w) = strict().await else { return };
    for i in 0..5 {
        invoice(&mut w, &format!("inv-{i}")).await;
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut ask = by_subject(USER, "invoice:read", "invoice");
    ask["page"] = json!({"limit": 2});
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let (status, body) = post(&w, RESOURCE, &token, &ask).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(ids(&body).len() <= 2);
        seen.extend(ids(&body).into_iter().map(str::to_owned));
        pages += 1;
        let next = body["page"]["next_token"].as_str().unwrap();
        if next.is_empty() {
            break;
        }
        ask["page"]["token"] = json!(next);
        assert!(pages < 10);
    }
    assert_eq!(seen.len(), 5);
    assert_eq!(seen.iter().collect::<BTreeSet<_>>().len(), 5);

    ask["page"] = json!({"limit": 1_000_000});
    let (status, body) = post(&w, RESOURCE, &token, &ask).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ids(&body).len(), 5);

    ask["page"] = json!({"token": "@@@"});
    let (status, body) = post(&w, RESOURCE, &token, &ask).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["type"], "urn:tutela:problem:invalid_page");
    w.finish().await;
}

#[tokio::test]
async fn a_subject_search_lists_who_check_allows_with_groups_expanded() {
    let Some(mut w) = strict().await else { return };
    {
        let World { d, a, .. } = &mut w;
        let group = tutela_pdp::model::GroupKey::parse("team").unwrap();
        let org = a.org.org_id().unwrap();
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::create_group(&tx, &a.key, &org, &group, "Team")
            .await
            .unwrap();
        tutela_store::add_member(
            &tx,
            &a.key,
            &group,
            &tutela_pdp::Member::Principal(STRANGER.parse().unwrap()),
            None,
        )
        .await
        .unwrap();
        tutela_store::assign(
            &tx,
            &a.key,
            &tutela_pdp::Subject::Group(group),
            &tutela_pdp::model::RoleKey::parse("reader").unwrap(),
            &a.project,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (status, body) = post(&w, SUBJECT, &token, &who_may("user", "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ids(&body), [USER, STRANGER]);
    assert_eq!(body["results"][0]["type"], "user");

    // Agreeing with `check`: each one is allowed, and write is held by none.
    let (_, none) = post(&w, SUBJECT, &token, &who_may("user", "invoice:write", &w.a)).await;
    assert_eq!(none["results"], json!([]));
    let (_, kinds) = post(&w, SUBJECT, &token, &who_may("agent", "invoice:read", &w.a)).await;
    assert_eq!(kinds["results"], json!([]));

    let mut paged = who_may("user", "invoice:read", &w.a);
    paged["page"] = json!({"limit": 1});
    let (_, first) = post(&w, SUBJECT, &token, &paged).await;
    assert_eq!(ids(&first), [USER]);
    paged["page"]["token"] = first["page"]["next_token"].clone();
    let (_, second) = post(&w, SUBJECT, &token, &paged).await;
    assert_eq!(ids(&second), [STRANGER]);
    assert_eq!(second["page"]["next_token"], "");
    w.finish().await;
}

#[tokio::test]
async fn a_search_refuses_a_bad_request_and_never_guesses() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    for body in [
        json!({"subject": {"type": "user", "id": USER}, "action": {"name": "invoice:read"}}),
        by_subject(USER, "project:read", "invoice"),
        by_subject(USER, "invoice:nothing", "invoice"),
    ] {
        let (status, p) = post(&w, RESOURCE, &token, &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {p}");
    }
    let (status, _) = post(&w, SUBJECT, &token, &who_may("robot", "invoice:read", &w.a)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(
        &w,
        SUBJECT,
        &token,
        &who_may("user", "invoice:nothing", &w.a),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    w.finish().await;
}

#[tokio::test]
async fn a_revision_the_database_has_not_reached_is_503_for_a_search() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut ask = by_subject(USER, "invoice:read", "invoice");
    ask["context"] = json!({"at_least_revision": 99_999});
    let (status, _) = post(&w, RESOURCE, &token, &ask).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let mut ask = who_may("user", "invoice:read", &w.a);
    ask["context"] = json!({"at_least_revision": 99_999});
    let (status, _) = post(&w, SUBJECT, &token, &ask).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    w.finish().await;
}

#[tokio::test]
async fn searches_need_a_token() {
    let Some(w) = world().await else { return };
    for path in [RESOURCE, SUBJECT] {
        let r = http()
            .post(w.s.api_url(path))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    w.finish().await;
}

/// A manifest with a field condition: a resource it covers is not named,
/// and the filter carries the condition for the product's own SQL.
#[tokio::test]
async fn a_resource_behind_a_field_condition_is_left_to_the_filter() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    let conditional = common::MANIFEST
        .replace(
            r#"status = { sensitivity = "internal" }"#,
            "status = { sensitivity = \"internal\" }\n\
             assignee = { sensitivity = \"internal\", type = \"principal\", grants_access = true }",
        )
        .replace(
            r#"[ui."invoices.approve_button"]"#,
            "[[conditions]]\nrole = \"reader\"\ntype = \"invoice\"\n\
             when = { is_principal = \"assignee\" }\nelse = \"none\"\n\n\
             [ui.\"invoices.approve_button\"]",
        );
    publish(&mut w.d.owner, &conditional, Some(1)).await;
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (status, body) = post(
        &w,
        RESOURCE,
        &token,
        &by_subject(USER, "invoice:read", "invoice"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(ids(&body).is_empty(), "{body}");
    let filter = &body["context"]["tutela"]["filter"];
    assert_eq!(filter["container_in"][0]["id"], "p-1");
    assert!(filter.get("condition").is_some(), "{body}");
    w.finish().await;
}

#[tokio::test]
async fn searches_are_counted_and_listed_in_the_metadata() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    post(
        &w,
        RESOURCE,
        &token,
        &by_subject(STRANGER, "invoice:read", "invoice"),
    )
    .await;
    let text = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains(r#"tutelad_decisions_total{operation="search_resource",outcome="deny"} 1"#),
        "{text}"
    );
    let m: Value = http()
        .get(w.s.api_url("/.well-known/authzen-configuration"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        m["search_resource_endpoint"]
            .as_str()
            .unwrap()
            .ends_with(RESOURCE)
    );
    assert!(
        m["search_subject_endpoint"]
            .as_str()
            .unwrap()
            .ends_with(SUBJECT)
    );
    assert!(m.get("search_action_endpoint").is_none());
    w.finish().await;
}

// ---------- gRPC ----------

fn with_token<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn subject(p: &str) -> pb::Subject {
    pb::Subject {
        r#type: kind(p).to_owned(),
        id: p.to_owned(),
        act: None,
    }
}

#[tokio::test]
async fn grpc_searches_answer_as_http_does() {
    let Some(mut w) = strict().await else { return };
    invoice(&mut w, "inv-1").await;
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AuthzClient::new(channel);

    let resources = pb::SearchRequest {
        subject: Some(subject(USER)),
        action: Some(pb::Action {
            name: "invoice:read".to_owned(),
        }),
        resource: Some(pb::Resource {
            r#type: "invoice".to_owned(),
            ..pb::Resource::default()
        }),
        ..pb::SearchRequest::default()
    };
    let g = client
        .search_resource(with_token(&token, resources.clone()))
        .await
        .unwrap()
        .into_inner();
    let (_, h) = post(
        &w,
        RESOURCE,
        &token,
        &by_subject(USER, "invoice:read", "invoice"),
    )
    .await;
    let got: Vec<&str> = g.results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(got, ids(&h));
    assert_eq!(json!(g.rev), h["context"]["tutela"]["rev"]);
    let filter: Value = serde_json::from_str(&g.filter_json).unwrap();
    assert_eq!(filter, h["context"]["tutela"]["filter"]);

    let entry = |e: &tutela_pdp::PathEntry| pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    };
    let subjects = pb::SearchRequest {
        subject: Some(pb::Subject {
            r#type: "user".to_owned(),
            ..pb::Subject::default()
        }),
        action: Some(pb::Action {
            name: "invoice:read".to_owned(),
        }),
        resource: Some(pb::Resource {
            r#type: "invoice".to_owned(),
            id: "inv-1".to_owned(),
            path: vec![entry(&w.a.project), entry(&w.a.org)],
            ..pb::Resource::default()
        }),
        ..pb::SearchRequest::default()
    };
    let g = client
        .search_subject(with_token(&token, subjects.clone()))
        .await
        .unwrap()
        .into_inner();
    let got: Vec<&str> = g.results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(got, [USER]);

    let person = w.issuer.token(USER, &w.a.tid, 0);
    let e = client
        .search_subject(with_token(&person, subjects))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    let e = client
        .search_resource(tonic::Request::new(resources))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    w.finish().await;
}
