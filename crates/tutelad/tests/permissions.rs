//! The UI permission map through the real auth layer and a real Postgres.
#![cfg(test)]

mod common;

use std::time::{Duration, SystemTime};

use common::{AGENT, B_USER, SA, STRANGER, Seed, USER, World, http, publish, world, world_with};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutelad::authz::grpc::pb;
use tutelad::authz::grpc::pb::authz_client::AuthzClient;

const MAP: &str = "/v1/authz/permissions";
const EVAL: &str = "/access/v1/evaluation";

fn map_of(subject: &str, s: &Seed) -> Value {
    json!({
        "subject": {"type": subject.split(':').next().unwrap(), "id": subject},
        "resource": {"type": "invoice", "id": "inv-1", "path": common::path(s)},
    })
}

async fn post(w: &World, token: &str, body: &Value, etag: Option<&str>) -> reqwest::Response {
    let mut r = http().post(w.s.api_url(MAP)).bearer_auth(token).json(body);
    if let Some(tag) = etag {
        r = r.header("if-none-match", tag);
    }
    r.send().await.unwrap()
}

/// The map and its tag.
async fn fetch(w: &World, token: &str, body: &Value) -> (Value, String) {
    let r = post(w, token, body, None).await;
    assert_eq!(r.status(), StatusCode::OK);
    let tag = r.headers()["etag"].to_str().unwrap().to_owned();
    (r.json().await.unwrap(), tag)
}

fn long_lease(c: &mut tutelad::Config) {
    c.limits.check_every = Duration::from_secs(60);
}

fn strict(c: &mut tutelad::Config) {
    c.limits.check_every = Duration::ZERO;
}

/// One write that changes no answer of this test.
async fn bump(w: &mut World) -> u64 {
    let World { d, a, .. } = w;
    let tx = d.owner.transaction().await.unwrap();
    let scope = tutela_pdp::PathEntry::new(
        "project".parse().unwrap(),
        format!("p-{}", uuid::Uuid::now_v7().simple())
            .parse()
            .unwrap(),
    );
    let rev = tutela_store::put_scope(&tx, &a.key, &scope, std::slice::from_ref(&a.org), false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rev
}

#[tokio::test]
async fn the_map_gives_each_mode_and_agrees_with_check() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut body = map_of(USER, &w.a);
    body["actions"] = json!(["invoice:read", "invoice:approve"]);
    body["fields"] = json!(["invoice.status", "invoice.amount", "project.nothing"]);
    let (map, _) = fetch(&w, &token, &body).await;
    let ui = &map["ui"];
    assert_eq!(ui["invoices.approve_button"]["mode"], "disable", "{map}");
    assert!(ui["invoices.approve_button"]["reason"].is_string(), "{map}");
    assert_eq!(ui["invoices.delete_button"]["mode"], "hide");
    assert!(ui["invoices.delete_button"].get("reason").is_none());
    // `readonly` shows a value, and this reader may not read it.
    assert_eq!(ui["invoices.amount_cell"]["mode"], "hide", "{map}");
    // A key about another type cannot be decided on an invoice.
    assert_eq!(ui["projects.settings"]["mode"], "hide");
    assert_eq!(map["actions"]["invoice:read"], true);
    assert_eq!(map["actions"]["invoice:approve"], false);
    assert_eq!(map["fields"]["invoice.status"], "read");
    assert_eq!(map["fields"]["invoice.amount"], "none");
    assert_eq!(map["fields"]["project.nothing"], "none");

    for (action, want) in [("invoice:read", true), ("invoice:approve", false)] {
        let d: Value = w
            .post(EVAL, &token, &common::ask(USER, action, &w.a))
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(d["decision"], want, "{action}");
        assert_eq!(map["rev"], d["context"]["tutela"]["rev"]);
    }
    w.finish().await;
}

#[tokio::test]
async fn an_allowed_subject_gets_show_and_a_read_only_field_gets_readonly() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.b.tid, 0);
    let (map, _) = fetch(&w, &token, &map_of(B_USER, &w.b)).await;
    let ui = &map["ui"];
    assert_eq!(ui["invoices.approve_button"]["mode"], "show", "{map}");
    assert!(ui["invoices.approve_button"].get("reason").is_none());
    assert_eq!(ui["invoices.status_cell"]["mode"], "show", "{map}");
    // Only `delete` needs Full, which the approver does not have.
    assert_eq!(ui["invoices.delete_button"]["mode"], "hide");

    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (map, _) = fetch(&w, &token, &map_of(USER, &w.a)).await;
    assert_eq!(
        map["ui"]["invoices.status_cell"]["mode"], "readonly",
        "{map}"
    );
    w.finish().await;
}

#[tokio::test]
async fn a_map_names_only_reasons_that_are_safe_to_show() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (map, _) = fetch(&w, &token, &map_of(STRANGER, &w.a)).await;
    assert_eq!(
        map["ui"]["invoices.approve_button"]["reason"], "not_allowed",
        "`no_role` must not reach a UI: {map}"
    );
    w.finish().await;
}

#[tokio::test]
async fn a_map_asks_only_for_the_keys_it_names_and_refuses_what_is_not_there() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut body = map_of(USER, &w.a);
    body["ui_keys"] = json!(["invoices.delete_button"]);
    let (map, _) = fetch(&w, &token, &body).await;
    assert_eq!(map["ui"].as_object().unwrap().len(), 1);

    body["ui_keys"] = json!(["invoices.nothing"]);
    let r = post(&w, &token, &body, None).await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    let mut body = map_of(USER, &w.a);
    body["actions"] = json!(["invoice:nothing"]);
    assert_eq!(
        post(&w, &token, &body, None).await.status(),
        StatusCode::BAD_REQUEST
    );

    let mut body = map_of(USER, &w.a);
    body["actions"] = json!(vec!["invoice:read"; 2001]);
    assert_eq!(
        post(&w, &token, &body, None).await.status(),
        StatusCode::BAD_REQUEST
    );
    w.finish().await;
}

#[tokio::test]
async fn the_same_request_gets_a_304_with_the_same_tag_and_no_body() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = map_of(USER, &w.a);
    let (map, tag) = fetch(&w, &token, &body).await;
    assert_eq!(
        tag,
        format!(
            "\"r{}-{}\"",
            map["rev"],
            &tag[tag.len() - 17..tag.len() - 1]
        ),
        "{tag}"
    );
    let r = post(&w, &token, &body, Some(&tag)).await;
    assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(r.headers()["etag"], tag.as_str());
    assert_eq!(r.headers()["cache-control"], "private, no-cache");
    assert!(r.bytes().await.unwrap().is_empty());

    // A weak form and a list work; a star never does: it holds no map.
    let weak = format!("W/{tag}");
    assert_eq!(
        post(&w, &token, &body, Some(&weak)).await.status(),
        StatusCode::NOT_MODIFIED
    );
    let list = format!("\"r0-0000000000000000\", {tag}");
    assert_eq!(
        post(&w, &token, &body, Some(&list)).await.status(),
        StatusCode::NOT_MODIFIED
    );
    assert_eq!(
        post(&w, &token, &body, Some("*")).await.status(),
        StatusCode::OK
    );
    w.finish().await;
}

#[tokio::test]
async fn the_tag_changes_with_the_revision_even_when_the_map_does_not() {
    let Some(mut w) = world_with(strict).await else {
        return;
    };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = map_of(USER, &w.a);
    let (before, old) = fetch(&w, &token, &body).await;
    let rev = bump(&mut w).await;
    let r = post(&w, &token, &body, Some(&old)).await;
    assert_eq!(r.status(), StatusCode::OK);
    let new = r.headers()["etag"].to_str().unwrap().to_owned();
    assert_ne!(new, old);
    assert!(new.starts_with(&format!("\"r{rev}-")), "{new}");
    let mut after: Value = r.json().await.unwrap();
    after["rev"] = before["rev"].clone();
    assert_eq!(after, before, "only the revision moved");
    w.finish().await;
}

#[tokio::test]
async fn the_tag_changes_with_the_model() {
    let Some(mut w) = world_with(strict).await else {
        return;
    };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = map_of(USER, &w.a);
    let (_, old) = fetch(&w, &token, &body).await;
    let changed = common::MANIFEST.replace(
        r#"reason      = "Only approvers can approve.""#,
        r#"reason      = "Approvers only.""#,
    );
    publish(&mut w.d.owner, &changed, Some(1)).await;
    let r = post(&w, &token, &body, Some(&old)).await;
    assert_eq!(r.status(), StatusCode::OK, "a new model is never a 304");
    assert_ne!(r.headers()["etag"].to_str().unwrap(), old);
    w.finish().await;
}

/// The same revision and the same map, and only the model moved: the
/// stored manifest changes with no publish, and an expiry makes the replica
/// load it. The tag must still change.
#[tokio::test]
async fn the_tag_covers_the_model_by_itself() {
    let Some(mut w) = world_with(strict).await else {
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
            SystemTime::now() + Duration::from_millis(900),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = map_of(USER, &w.a);
    let (before, old) = fetch(&w, &token, &body).await;

    let changed = common::MANIFEST.replace("Only approvers can approve.", "Approvers only.");
    let digest = tutela_store::digest(&changed);
    w.d.owner
        .execute(
            "UPDATE tutela.app_manifest SET source = $1, digest = $2",
            &[&changed, &digest],
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let r = post(&w, &token, &body, Some(&old)).await;
    assert_eq!(r.status(), StatusCode::OK, "a 304 would hide the new model");
    let new = r.headers()["etag"].to_str().unwrap().to_owned();
    assert_ne!(new, old);
    let after: Value = r.json().await.unwrap();
    assert_eq!(after, before, "the same map at the same revision");
    w.finish().await;
}

/// Two principals with the same map at the same revision: one's tag must
/// not answer for the other.
#[tokio::test]
async fn one_principals_tag_never_answers_for_another() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (mine, tag) = fetch(&w, &token, &map_of(STRANGER, &w.a)).await;
    let (theirs, other) = fetch(&w, &token, &map_of(B_USER, &w.a)).await;
    assert_eq!(mine, theirs, "the same map, for this to mean anything");
    assert_ne!(tag, other);
    let r = post(&w, &token, &map_of(B_USER, &w.a), Some(&tag)).await;
    assert_eq!(r.status(), StatusCode::OK);

    w.finish().await;
}

/// An agent with the person's own role gives the same map, so only the
/// actor tells the two questions apart.
#[tokio::test]
async fn a_tag_of_a_person_alone_never_answers_for_the_person_through_an_agent() {
    let Some(mut w) = world_with(strict).await else {
        return;
    };
    {
        let World { d, a, .. } = &mut w;
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::assign(
            &tx,
            &a.key,
            &tutela_pdp::Subject::Principal(AGENT.parse().unwrap()),
            &tutela_pdp::model::RoleKey::parse("reader").unwrap(),
            &a.project,
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let plain = map_of(USER, &w.a);
    let mut through = plain.clone();
    through["subject"]["properties"] = json!({"act": {"sub": AGENT}});
    let (alone, tag) = fetch(&w, &token, &plain).await;
    let (with_agent, other) = fetch(&w, &token, &through).await;
    assert_eq!(alone, with_agent, "the same map, for this to mean anything");
    assert_ne!(tag, other);
    let r = post(&w, &token, &through, Some(&tag)).await;
    assert_eq!(r.status(), StatusCode::OK);
    w.finish().await;
}

#[tokio::test]
async fn one_tenants_tag_never_answers_for_another() {
    let Some(w) = world().await else { return };
    let a = w.issuer.token(SA, &w.a.tid, 0);
    let b = w.issuer.token(SA, &w.b.tid, 0);
    let (_, tag) = fetch(&w, &a, &map_of(STRANGER, &w.a)).await;
    // The same bytes in the request, and the revisions are the same.
    let r = post(&w, &b, &map_of(STRANGER, &w.a), Some(&tag)).await;
    assert_eq!(r.status(), StatusCode::OK);
    w.finish().await;
}

#[tokio::test]
async fn the_tag_changes_with_the_request() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (first, tag) = fetch(&w, &token, &map_of(USER, &w.a)).await;
    // Another invoice under the same project: the same map, another
    // question.
    let mut other = map_of(USER, &w.a);
    other["resource"]["id"] = json!("inv-2");
    let r = post(&w, &token, &other, Some(&tag)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_ne!(r.headers()["etag"].to_str().unwrap(), tag);
    let second: Value = r.json().await.unwrap();
    assert_eq!(first, second, "the same map, for this to mean anything");
    w.finish().await;
}

/// An assignment expires and the revision does not move, because no sweep
/// has run. A tag of (revision, request) would say 304, and the UI would
/// keep a button the person lost.
#[tokio::test]
async fn an_expiry_at_one_revision_is_not_a_304() {
    let Some(mut w) = world_with(long_lease).await else {
        return;
    };
    {
        let World { d, a, .. } = &mut w;
        let tx = d.owner.transaction().await.unwrap();
        tutela_store::assign_until(
            &tx,
            &a.key,
            &tutela_pdp::Subject::Principal(STRANGER.parse().unwrap()),
            &tutela_pdp::model::RoleKey::parse("approver").unwrap(),
            &a.project,
            None,
            SystemTime::now() + Duration::from_millis(1200),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let body = map_of(STRANGER, &w.a);
    let (before, tag) = fetch(&w, &token, &body).await;
    assert_eq!(
        before["ui"]["invoices.approve_button"]["mode"], "show",
        "{before}"
    );
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let r = post(&w, &token, &body, Some(&tag)).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "a stale 304 would keep the button"
    );
    let after: Value = r.json().await.unwrap();
    assert_eq!(after["rev"], before["rev"], "the revision did not move");
    assert_eq!(after["ui"]["invoices.approve_button"]["mode"], "disable");
    w.finish().await;
}

#[tokio::test]
async fn a_caller_who_may_not_ask_gets_no_map_and_no_304() {
    let Some(w) = world().await else { return };
    let service = w.issuer.token(SA, &w.a.tid, 0);
    let (_, tag) = fetch(&w, &service, &map_of(STRANGER, &w.a)).await;
    let person = w.issuer.token(USER, &w.a.tid, 0);
    let r = post(&w, &person, &map_of(STRANGER, &w.a), Some(&tag)).await;
    assert_eq!(
        r.status(),
        StatusCode::FORBIDDEN,
        "a 304 would confirm the map"
    );
    let r = post(&w, &person, &map_of(USER, &w.a), None).await;
    assert_eq!(r.status(), StatusCode::OK);
    let none = http()
        .post(w.s.api_url(MAP))
        .json(&map_of(USER, &w.a))
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), StatusCode::UNAUTHORIZED);
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_map_across_tenants_is_all_denied_and_names_nothing() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (map, _) = fetch(&w, &token, &map_of(B_USER, &w.b)).await;
    for (key, answer) in map["ui"].as_object().unwrap() {
        assert_ne!(answer["mode"], "show", "{key}");
        assert_ne!(answer["reason"], "tenant_mismatch", "{key}");
    }
    w.finish().await;
}

#[tokio::test]
async fn a_map_never_comes_from_an_older_revision() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let mut body = map_of(USER, &w.a);
    body["at_least_revision"] = json!(99_999);
    let r = post(&w, &token, &body, None).await;
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(r.headers()["retry-after"], "1");
    w.finish().await;
}

#[tokio::test]
async fn map_decisions_are_counted() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    fetch(&w, &token, &map_of(USER, &w.a)).await;
    let text = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains(r#"tutelad_decisions_total{operation="permissions",outcome="deny"}"#),
        "{text}"
    );
    w.finish().await;
}

#[tokio::test]
async fn grpc_gives_the_same_map_and_the_same_tag() {
    let Some(w) = world().await else { return };
    let token = w.issuer.token(SA, &w.a.tid, 0);
    let (http_map, tag) = fetch(&w, &token, &map_of(USER, &w.a)).await;
    let entry = |e: &tutela_pdp::PathEntry| pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    };
    let request = |if_none_match: &str| {
        let mut req = tonic::Request::new(pb::PermissionsRequest {
            subject: Some(pb::Subject {
                r#type: "user".to_owned(),
                id: USER.to_owned(),
                act: None,
            }),
            resource: Some(pb::Resource {
                r#type: "invoice".to_owned(),
                id: "inv-1".to_owned(),
                path: vec![entry(&w.a.project), entry(&w.a.org)],
                ..pb::Resource::default()
            }),
            if_none_match: if_none_match.to_owned(),
            ..pb::PermissionsRequest::default()
        });
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    };
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = AuthzClient::new(channel);
    let g = client.permissions(request("")).await.unwrap().into_inner();
    assert_eq!(g.etag, tag);
    assert!(!g.not_modified);
    assert_eq!(json!(g.rev), http_map["rev"]);
    for (key, answer) in http_map["ui"].as_object().unwrap() {
        assert_eq!(json!(g.ui[key].mode), answer["mode"], "{key}");
    }
    let same = client
        .permissions(request(&tag))
        .await
        .unwrap()
        .into_inner();
    assert!(same.not_modified);
    assert!(same.ui.is_empty());
    assert_eq!(same.etag, tag);

    let mut unauthenticated = request("");
    unauthenticated.metadata_mut().remove("authorization");
    let e = client.permissions(unauthenticated).await.unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    w.finish().await;
}
