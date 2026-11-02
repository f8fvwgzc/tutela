//! The admin API, `tutela.admin.v1` and its HTTP routes, through the real
//! auth layer on a real Postgres (CONTRACTS.md 7.13, ADR-0032, ADR-0040).
//! Every route is asked by denied principals and across tenants, over HTTP
//! and gRPC.
#![cfg(test)]

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::tokio_postgres::Client;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;

use common::{AGENT, B_USER, SA, STEP_UP, Seed, USER, World, audited, events_of, http, world};

/// An owner at every org of both tenants: a person, and a service.
const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b2";
/// The owner of project p-1 of tenant A only.
const PROJECT_OWNER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b3";
const WORKLOAD: &str = "spiffe://prod.attache.example.test/ns/shop/svc/orders";

async fn assign(owner: &mut Client, s: &Seed, who: &str, role: &str, at: &tutela_pdp::PathEntry) {
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

async fn admins(w: &mut World) {
    for s in [&w.a, &w.b] {
        let org = s.org.clone();
        assign(&mut w.d.owner, s, ADMIN, "owner", &org).await;
        assign(&mut w.d.owner, s, ADMIN_SA, "owner", &org).await;
    }
    let p = w.a.project.clone();
    assign(&mut w.d.owner, &w.a, PROJECT_OWNER, "owner", &p).await;
}

/// What the Console (a person after step-up) or a pipeline (a service)
/// sends.
fn console(w: &World, who: &str, s: &Seed) -> String {
    w.issuer.console(who, &s.tid, 0)
}

async fn call(
    w: &World,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> (StatusCode, Value) {
    let mut r = http().request(method, w.s.api_url(path));
    if let Some(t) = token {
        r = r.bearer_auth(t);
    }
    if let Some(b) = body {
        r = r.json(b);
    }
    let res = r.send().await.unwrap();
    let status = res.status();
    let text = res.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn post(w: &World, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
    call(w, reqwest::Method::POST, path, Some(token), Some(body)).await
}

fn problem(v: &Value) -> &str {
    v["type"]
        .as_str()
        .and_then(|t| t.strip_prefix("urn:tutela:problem:"))
        .unwrap_or("")
}

async fn grpc(w: &World) -> AdminClient<tonic::transport::Channel> {
    let channel = tonic::transport::Endpoint::from_shared(w.s.api_url(""))
        .unwrap()
        .connect()
        .await
        .unwrap();
    AdminClient::new(channel)
}

fn with_token<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

async fn whoami(w: &World, token: &str) -> StatusCode {
    call(w, reqwest::Method::GET, "/v1/whoami", Some(token), None)
        .await
        .0
}

/// Waits until `token` is refused on the API, at most 2.5 s (the revision
/// lease, ADR-0031 item 8).
async fn until_refused(w: &World, token: &str) {
    let start = std::time::Instant::now();
    while whoami(w, token).await != StatusCode::UNAUTHORIZED {
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "the disabled principal's token still works"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn until_accepted(w: &World, token: &str) {
    let start = std::time::Instant::now();
    while whoami(w, token).await != StatusCode::OK {
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "the enabled principal's new token is still refused"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn register(w: &World, token: &str, workload: Option<&str>) -> (StatusCode, Value) {
    post(
        w,
        "/v1/admin/agents",
        token,
        &json!({ "workload": workload }),
    )
    .await
}

#[tokio::test]
async fn tm01_the_admin_api_takes_a_persons_admin_token_and_a_services_own_token() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let tid = w.a.tid.clone();
    let person = console(&w, ADMIN, &w.a);
    let service = console(&w, ADMIN_SA, &w.a);
    let mut g = grpc(&w).await;

    // Allowed: a person's admin token after step-up; a service's own token.
    for t in [&person, &service] {
        let (status, v) = register(&w, t, None).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert!(v["principal"].as_str().unwrap().starts_with("agent:agt_"));
        let r = g
            .register_agent(with_token(t, pb::RegisterAgentRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert!(r.principal.starts_with("agent:agt_"));
    }

    // Refused, HTTP and gRPC alike: 403 / PERMISSION_DENIED.
    let denied = [
        (
            "a person's plain tutela-authz token",
            w.issuer.token(ADMIN, &tid, 0),
        ),
        (
            "a service's admin token",
            w.issuer.admin_token(ADMIN_SA, &tid, STEP_UP, 0, 300),
        ),
        (
            "a person's admin token without step-up",
            w.issuer.admin_token(ADMIN, &tid, "pwd", 0, 300),
        ),
        ("a delegated token", w.issuer.delegated(ADMIN, AGENT, &tid)),
        ("an agent's own token", w.issuer.token(AGENT, &tid, 0)),
        ("a service with no admin key", w.issuer.token(SA, &tid, 0)),
        (
            "a person with no admin key",
            w.issuer.console(USER, &tid, 0),
        ),
    ];
    for (what, t) in &denied {
        let (status, v) = register(&w, t, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {v}");
        assert_eq!(problem(&v), "forbidden", "{what}");
        let e = g
            .register_agent(with_token(t, pb::RegisterAgentRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::PermissionDenied, "{what}: {e:?}");
        for (path, body) in [
            ("/v1/admin/principals/state", json!({"principal": USER})),
            (
                "/v1/admin/principals/disabled",
                json!({"principal": USER, "disabled": true}),
            ),
            (
                "/v1/admin/principals/revoke-sessions",
                json!({"principal": USER}),
            ),
            (
                "/v1/admin/resource-types",
                json!({"types": {"x": {"parent": "org"}}}),
            ),
        ] {
            let (status, v) = post(&w, path, t, &body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{what} at {path}: {v}");
        }
    }

    // No token, or a token that does not verify: 401 / UNAUTHENTICATED.
    let (status, _) = call(
        &w,
        reqwest::Method::POST,
        "/v1/admin/agents",
        None,
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let e = g
        .register_agent(tonic::Request::new(pb::RegisterAgentRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    let six_minutes = w.issuer.admin_token(ADMIN, &tid, STEP_UP, 0, 360);
    let (status, _) = register(&w, &six_minutes, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // An admin token stays refused on a route outside the admin API.
    let (status, _) = post(
        &w,
        "/access/v1/evaluation",
        &person,
        &common::ask(USER, "invoice:read", &w.a),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Each refusal for want of a key was recorded with who asked.
    let refused = audited(&mut w.d.owner, &w.a.key, "tutela_principal:register").await;
    let denied_by: Vec<&str> = refused
        .iter()
        .filter(|r| r["outcome"] == "denied")
        .map(|r| r["actor"]["id"].as_str().unwrap())
        .collect();
    assert!(denied_by.contains(&SA), "{refused:?}");
    assert!(denied_by.contains(&USER), "{refused:?}");
    let ok_by: Vec<&str> = refused
        .iter()
        .filter(|r| r["outcome"] == "success")
        .map(|r| r["actor"]["id"].as_str().unwrap())
        .collect();
    assert_eq!(ok_by.iter().filter(|a| **a == ADMIN).count(), 2);
    assert_eq!(ok_by.iter().filter(|a| **a == ADMIN_SA).count(), 2);

    let metrics = http()
        .get(w.s.ops_url("/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        metrics.contains(
            "tutelad_admin_operations_total{operation=\"register_agent\",outcome=\"forbidden\"}"
        ),
        "{metrics}"
    );
    w.finish().await;
}

#[tokio::test]
async fn tm02_attache_registers_quarantines_and_enables_an_agent() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let attache = console(&w, ADMIN_SA, &w.a);
    let tid = w.a.tid.clone();

    let (status, v) = register(&w, &attache, Some(WORKLOAD)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let agent = v["principal"].as_str().unwrap().to_owned();
    assert_eq!(v["workload"], WORKLOAD);
    assert_eq!(
        (v["epoch"].as_u64(), v["disabled"].as_bool()),
        (Some(0), Some(false))
    );
    // One workload names one agent; a path that is not attache's is refused.
    let (status, v) = register(&w, &attache, Some(WORKLOAD)).await;
    assert_eq!((status, problem(&v)), (StatusCode::CONFLICT, "exists"));
    let (status, _) = register(
        &w,
        &attache,
        Some("spiffe://prod.attache.example.test/sa/orders"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = register(&w, &attache, Some("https://example.test")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Found again by its workload.
    let (status, v) = call(
        &w,
        reqwest::Method::GET,
        &format!("/v1/admin/agents?workload={WORKLOAD}"),
        Some(&attache),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["agents"][0]["principal"], agent.as_str());

    // Quarantine: disabled over gRPC, its token stops on the API.
    let token = w.issuer.token(&agent, &tid, 0);
    assert_eq!(whoami(&w, &token).await, StatusCode::OK);
    let mut g = grpc(&w).await;
    let s = g
        .set_disabled(with_token(
            &attache,
            pb::SetDisabledRequest {
                principal: agent.clone(),
                disabled: true,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(s.disabled);
    assert_eq!(s.epoch, 1);
    assert!(s.rev > 0);
    until_refused(&w, &token).await;
    let (_, v) = post(
        &w,
        "/v1/admin/principals/state",
        &attache,
        &json!({"principal": agent}),
    )
    .await;
    assert_eq!(v["disabled"], true, "{v}");

    // Enabled again over HTTP: the old token stays refused, a new one works.
    let (status, v) = post(
        &w,
        "/v1/admin/principals/disabled",
        &attache,
        &json!({"principal": agent, "disabled": false}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        (v["disabled"].as_bool(), v["epoch"].as_u64()),
        (Some(false), Some(1))
    );
    let now = common::now();
    let fresh = w.issuer.sign_claims(&json!({
        "iss": common::ISS, "sub": agent, "aud": common::AUD, "azp": "attache",
        "exp": now + 300, "iat": now, "nbf": now, "jti": uuid::Uuid::now_v7().to_string(),
        "tid": tid, "epoch": 1, "rev": 0,
    }));
    until_accepted(&w, &fresh).await;
    assert_eq!(whoami(&w, &token).await, StatusCode::UNAUTHORIZED);

    // A person's sessions are revoked through the same API.
    let (status, v) = post(
        &w,
        "/v1/admin/principals/revoke-sessions",
        &console(&w, ADMIN, &w.a),
        &json!({"principal": USER}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["epoch"], 1);
    until_refused(&w, &w.issuer.token(USER, &tid, 0)).await;

    // The events of CONTRACTS.md 8.3, in the changes' transactions.
    let types: Vec<String> = events_of(&mut w.d.owner, &w.a.key)
        .await
        .iter()
        .map(|e| e.event_type.to_string())
        .collect();
    for t in [
        "tutela.principal.disabled.v1",
        "tutela.principal.enabled.v1",
        "tutela.session.revoked.v1",
    ] {
        assert!(types.iter().any(|x| x == t), "{t} in {types:?}");
    }
    // Each change has its record, with who asked and the new epoch.
    for (action, by, epoch) in [
        ("tutela_principal:register", ADMIN_SA, None),
        ("tutela_principal:disable", ADMIN_SA, Some(1)),
        ("tutela_principal:enable", ADMIN_SA, Some(1)),
        ("tutela_principal:revoke_sessions", ADMIN, Some(1)),
    ] {
        let r = audited(&mut w.d.owner, &w.a.key, action).await;
        let ok: Vec<&Value> = r.iter().filter(|r| r["outcome"] == "success").collect();
        assert!(!ok.is_empty(), "{action}");
        assert_eq!(ok[0]["actor"]["id"], by, "{action}");
        if let Some(e) = epoch {
            assert_eq!(ok[0]["details"]["epoch"], e, "{action}");
        }
    }
    w.finish().await;
}

#[tokio::test]
async fn tm05_an_agent_lives_in_its_own_tenant_only() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let a_admin = console(&w, ADMIN_SA, &w.a);
    let b_admin = console(&w, ADMIN_SA, &w.b);
    let (_, v) = register(&w, &b_admin, Some(WORKLOAD)).await;
    let b_agent = v["principal"].as_str().unwrap().to_owned();
    let mut g = grpc(&w).await;

    // Tenant A's admin cannot see, disable or revoke B's agent.
    for (path, body) in [
        ("/v1/admin/principals/state", json!({"principal": b_agent})),
        (
            "/v1/admin/principals/disabled",
            json!({"principal": b_agent, "disabled": true}),
        ),
        (
            "/v1/admin/principals/revoke-sessions",
            json!({"principal": b_agent}),
        ),
    ] {
        let (status, v) = post(&w, path, &a_admin, &body).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {v}");
    }
    let e = g
        .set_disabled(with_token(
            &a_admin,
            pb::SetDisabledRequest {
                principal: b_agent.clone(),
                disabled: true,
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    // The same workload is free in A: registration is per tenant.
    let (status, v) = register(&w, &a_admin, Some(WORKLOAD)).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let a_agent = v["principal"].as_str().unwrap().to_owned();
    let list = |t: String| {
        let w = &w;
        async move {
            let (_, v) = call(w, reqwest::Method::GET, "/v1/admin/agents", Some(&t), None).await;
            v["agents"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| a["principal"].as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(list(a_admin.clone()).await, vec![a_agent.clone()]);
    assert_eq!(list(b_admin.clone()).await, vec![b_agent.clone()]);
    // B's agent is untouched, and its token works in B only.
    let (_, v) = post(
        &w,
        "/v1/admin/principals/state",
        &b_admin,
        &json!({"principal": b_agent}),
    )
    .await;
    assert_eq!(
        (v["disabled"].as_bool(), v["epoch"].as_u64()),
        (Some(false), Some(0))
    );
    let b_token = w.issuer.token(&b_agent, &w.b.tid, 0);
    assert_eq!(whoami(&w, &b_token).await, StatusCode::OK);
    // A user of B disabled "in A" is a row of A only: B's user still works.
    let (status, _) = post(
        &w,
        "/v1/admin/principals/disabled",
        &a_admin,
        &json!({"principal": B_USER, "disabled": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        whoami(&w, &w.issuer.token(B_USER, &w.b.tid, 0)).await,
        StatusCode::OK
    );
    w.finish().await;
}

async fn put(w: &World, t: String, b: Value) -> (StatusCode, Value) {
    call(
        w,
        reqwest::Method::PUT,
        "/v1/admin/boundaries",
        Some(&t),
        Some(&b),
    )
    .await
}

#[tokio::test]
async fn tm08_a_scopes_rules_need_manage_boundaries_on_that_scope() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let scope = json!({"type": "project", "id": "p-1"});
    let body = json!({"scope": scope, "moves_out": "owners", "on_looser": "block"});

    // A reader of the project, and a service with no key: refused, recorded.
    for t in [console(&w, USER, &w.a), console(&w, SA, &w.a)] {
        let (status, v) = put(&w, t, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
    }
    let refused = audited(&mut w.d.owner, &w.a.key, "tutela_boundary:write").await;
    assert_eq!(
        refused.iter().filter(|r| r["outcome"] == "denied").count(),
        2
    );

    // The project's own owner may, and so may an org admin.
    let (status, v) = put(&w, console(&w, PROJECT_OWNER, &w.a), body.clone()).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    let (status, v) = put(
        &w,
        console(&w, ADMIN, &w.a),
        json!({"scope": scope, "moves_in": "members", "links_from": "team"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["rev"].as_u64().unwrap() > rev);

    // Over gRPC too, with the same rule.
    let mut g = grpc(&w).await;
    let req = |t: &str| {
        with_token(
            t,
            pb::SetBoundaryRequest {
                scope: Some(pb::PathEntry {
                    r#type: "project".into(),
                    id: "p-1".into(),
                }),
                moves_out: "members".into(),
                ..pb::SetBoundaryRequest::default()
            },
        )
    };
    let e = g
        .set_boundary(req(&console(&w, SA, &w.a)))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    let r = g
        .set_boundary(req(&console(&w, ADMIN_SA, &w.a)))
        .await
        .unwrap()
        .into_inner();
    assert!(r.rev > rev);

    // What is not a registered scope, or not a rule.
    let admin = console(&w, ADMIN, &w.a);
    for (b, want) in [
        (
            json!({"scope": {"type": "project", "id": "nope"}, "moves_out": "owners"}),
            StatusCode::NOT_FOUND,
        ),
        (
            json!({"scope": {"type": "org", "id": w.a.org.id.to_string()}, "moves_out": "owners"}),
            StatusCode::BAD_REQUEST,
        ),
        (
            json!({"scope": scope, "moves_out": "everyone"}),
            StatusCode::BAD_REQUEST,
        ),
        (json!({"moves_out": "owners"}), StatusCode::BAD_REQUEST),
    ] {
        let (status, v) = put(&w, admin.clone(), b.clone()).await;
        assert_eq!(status, want, "{b}: {v}");
    }

    // The rule is A's: B's project p-1 has none. The change emitted its
    // event, and its record names the scope and who asked.
    let mut load = async |key| {
        let tx = w.d.owner.transaction().await.unwrap();
        let bundle = tutela_store::load(&tx, key).await.unwrap();
        tx.commit().await.unwrap();
        bundle
    };
    let a = load(&w.a.key).await;
    let b = load(&w.b.key).await;
    let rule = a.data.boundaries.get(&w.a.project).unwrap();
    assert_eq!(rule.moves_out, Some(tutela_pdp::MoveRule::Members));
    assert!(b.data.boundaries.is_empty());
    assert!(
        events_of(&mut w.d.owner, &w.a.key)
            .await
            .iter()
            .any(|e| e.event_type.as_str() == "tutela.permissions.changed.v1"
                && e.data["rev"] == json!(r.rev))
    );
    let done: Vec<Value> = audited(&mut w.d.owner, &w.a.key, "tutela_boundary:write")
        .await
        .into_iter()
        .filter(|r| r["outcome"] == "success")
        .collect();
    assert_eq!(done.len(), 3);
    assert_eq!(done[0]["actor"]["id"], PROJECT_OWNER);
    assert_eq!(done[0]["details"]["scope_id"], "p-1");
    assert_eq!(done[0]["details"]["moves_out"], "owners");
    assert_eq!(done[0]["org"], w.a.org.id.to_string());
    w.finish().await;
}

#[tokio::test]
async fn the_model_routes_answer_over_grpc_as_over_http() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let person = console(&w, ADMIN, &w.a);
    let mut g = grpc(&w).await;
    let (_, http_list) = call(&w, reqwest::Method::GET, "/v1/models", Some(&person), None).await;
    let list = g
        .list_model_versions(with_token(&person, pb::ListModelVersionsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    let grpc_list: Value = serde_json::from_str(&list.result_json).unwrap();
    assert_eq!(grpc_list, http_list);
    let expected = grpc_list["active"]["version"].as_i64().unwrap();

    // A narrowing publish over gRPC by a person after step-up.
    let narrower = common::MANIFEST.replace(
        "grants = { project = \"read\", invoice = \"read\" }",
        "grants = { project = \"read\" }",
    );
    let out = g
        .publish_model(with_token(
            &person,
            pb::ModelChangeRequest {
                source: Some(narrower),
                expected_version: Some(expected),
                ..pb::ModelChangeRequest::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let out: Value = serde_json::from_str(&out.result_json).unwrap();
    assert_eq!(out["class"], "narrowing", "{out}");
    let published = audited(&mut w.d.owner, &w.a.key, "tutela_model:publish").await;
    assert_eq!(published.last().unwrap()["actor"]["id"], ADMIN);

    // A person's plain token, and a tenant without the keys, are refused.
    let e = g
        .list_model_versions(with_token(
            &w.issuer.token(ADMIN, &w.a.tid, 0),
            pb::ListModelVersionsRequest::default(),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    let e = g
        .get_model_version(with_token(
            &person,
            pb::GetModelVersionRequest { version: 999 },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    let e = g
        .publish_model(with_token(
            &person,
            pb::ModelChangeRequest {
                source: Some(common::MANIFEST.to_owned()),
                expected_version: Some(expected),
                ..pb::ModelChangeRequest::default()
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Aborted, "{e:?}");
    w.finish().await;
}

#[tokio::test]
async fn put_resource_types_stores_a_proposal_and_publishes_nothing() {
    let Some(mut w) = world().await else { return };
    admins(&mut w).await;
    let onto = console(&w, ADMIN_SA, &w.a);
    let person = console(&w, ADMIN, &w.a);
    let (_, before) = call(&w, reqwest::Method::GET, "/v1/models", Some(&person), None).await;
    let types = json!({
        "ticket": {"parent": "project", "fields": {
            "title": {"sensitivity": "internal"},
            "salary": {"sensitivity": "secret", "type": "integer"}}},
        "invoice": {"fields": {"memo": {"sensitivity": "secret"}}},
    });
    let (status, p) = post(
        &w,
        "/v1/admin/resource-types",
        &onto,
        &json!({"types": types}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(p["state"], "proposed");
    assert_eq!(p["proposed_by"], ADMIN_SA);
    // Nothing is published until a person approves.
    let (_, now) = call(&w, reqwest::Method::GET, "/v1/models", Some(&person), None).await;
    assert_eq!(now["active"], before["active"]);

    // Only new types and entries are taken.
    for (body, want) in [
        (
            json!({"types": {"invoice": {"fields": {"status": {"sensitivity": "public"}}}}}),
            "not_additive",
        ),
        (
            json!({"types": {"invoice": {"parent": "project"}}}),
            "no_change",
        ),
        (
            json!({"types": {"ticket": {"parent": "project"}}, "expected_version": 999}),
            "version_conflict",
        ),
    ] {
        let (status, v) = post(&w, "/v1/admin/resource-types", &onto, &body).await;
        assert_eq!(
            (status, problem(&v)),
            (StatusCode::CONFLICT, want),
            "{body}"
        );
    }
    let (status, v) = post(
        &w,
        "/v1/admin/resource-types",
        &onto,
        &json!({"types": {"broken": {"parent": "nowhere"}}}),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::BAD_REQUEST, "invalid_manifest"),
        "{v}"
    );

    // Over gRPC as well.
    let mut g = grpc(&w).await;
    let r = g
        .put_resource_types(with_token(
            &onto,
            pb::PutResourceTypesRequest {
                types_json: json!({"memo": {"parent": "project"}}).to_string(),
                expected_version: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let memo: Value = serde_json::from_str(&r.result_json).unwrap();
    assert_eq!(memo["state"], "proposed");

    // A person approves the first, with an approval token since a new type
    // widens what the owner role reaches; then the model has the new type.
    let id = p["id"].as_str().unwrap();
    let (status, v) = post(
        &w,
        &format!("/v1/models/proposals/{id}/approve"),
        &person,
        &json!({}),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "approval_required"),
        "{v}"
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let tx = w.d.owner.transaction().await.unwrap();
    let kid = tutela_store::add_approver(&tx, "dana", &key.verifying_key().to_bytes())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let now = common::now();
    let approval = tutela_store::approval::mint(
        &key,
        &tutela_store::approval::Approval {
            app: "crm".into(),
            from: p["from"].as_str().unwrap().into(),
            to: p["to"].as_str().unwrap().into(),
            kid,
            iat: now - 10,
            exp: now + 600,
            tid: Some(w.a.tid.clone()),
        },
    )
    .unwrap();
    let (status, v) = post(
        &w,
        &format!("/v1/models/proposals/{id}/approve"),
        &person,
        &json!({"approval": approval}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (_, after) = call(&w, reqwest::Method::GET, "/v1/models", Some(&person), None).await;
    let version = after["active"]["version"].as_i64().unwrap();
    assert!(version > before["active"]["version"].as_i64().unwrap());
    let (_, text) = call(
        &w,
        reqwest::Method::GET,
        &format!("/v1/models/{version}"),
        Some(&person),
        None,
    )
    .await;
    let model = tutela_pdp::model::Model::from_toml(text["source"].as_str().unwrap()).unwrap();
    assert!(model.types().contains_key(&"ticket".parse().unwrap()));

    let proposed = audited(&mut w.d.owner, &w.a.key, "tutela_proposal:propose").await;
    assert!(
        proposed
            .iter()
            .all(|r| r["details"]["origin"] == "resource_types"),
        "{proposed:?}"
    );
    w.finish().await;
}
