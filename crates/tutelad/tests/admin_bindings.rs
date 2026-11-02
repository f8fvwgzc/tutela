//! Scopes, role assignments and groups over the admin API (issue #107,
//! CONTRACTS.md 7.13.7, ADR-0043), through the real auth layer on a real
//! Postgres. Every route is asked by denied principals and across tenants,
//! over HTTP and gRPC; the narrow-only rule and the checked move are asked
//! by callers who hold too little.
#![cfg(test)]

mod common;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tonic::Code;
use tutela_pdp::Subject;
use tutela_pdp::model::RoleKey;
use tutela_store::tokio_postgres::Client;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;

use common::{AGENT, SA, STEP_UP, Seed, USER, World, audited, events_of, http};

/// An owner at every org of both tenants: a person, and a service.
const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c2";
/// The owner of project p-1 of tenant A only.
const PROJECT_OWNER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c3";
/// May manage access at p-1 of tenant A, and only reads there.
const KEEPER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c4";
const NEWCOMER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c5";
const OTHER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c6";
/// Reads everything in tenant A's org, and manages nothing.
const VIEWER: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c8";
const THIRD: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70c7";

/// The test manifest, with a folder that nests, and a role that may manage
/// access at a project while it only reads there.
fn manifest() -> String {
    format!(
        "{}\n{}",
        common::MANIFEST,
        r#"
[types.folder]
parent = ["project", "folder"]
container = true

[roles.keeper]
grants = { project = "read", invoice = "read", folder = "read", "project:manage_access" = true }
"#
    )
}

async fn world() -> Option<World> {
    let mut d = common::migrated().await?;
    common::publish(&mut d.owner, &manifest(), None).await;
    let a = common::seed(&mut d.owner, USER, "reader").await;
    let b = common::seed(&mut d.owner, common::B_USER, "approver").await;
    let issuer = common::Issuer::new();
    let cfg = common::config(
        &d.service_url,
        common::trust(&[a.tid.clone(), b.tid.clone()]),
    );
    let s = common::start(&cfg, common::state(&cfg, &issuer)).await;
    let mut w = World {
        d,
        issuer,
        a,
        b,
        s,
        config: cfg,
    };
    for s in [&w.a, &w.b] {
        let org = s.org.clone();
        assign(&mut w.d.owner, s, ADMIN, "owner", &org).await;
        assign(&mut w.d.owner, s, ADMIN_SA, "owner", &org).await;
    }
    let org = w.a.org.clone();
    assign(&mut w.d.owner, &w.a, VIEWER, "viewer", &org).await;
    let p = w.a.project.clone();
    assign(&mut w.d.owner, &w.a, PROJECT_OWNER, "owner", &p).await;
    assign(&mut w.d.owner, &w.a, KEEPER, "keeper", &p).await;
    Some(w)
}

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

fn console(w: &World, who: &str, s: &Seed) -> String {
    w.issuer.console(who, &s.tid, 0)
}

async fn call(
    w: &World,
    method: Method,
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

fn scope(e: &tutela_pdp::PathEntry) -> Value {
    json!({"type": e.type_name.to_string(), "id": e.id.to_string()})
}

fn path_entry(e: &tutela_pdp::PathEntry) -> pb::PathEntry {
    pb::PathEntry {
        r#type: e.type_name.to_string(),
        id: e.id.to_string(),
    }
}

fn entry(t: &str, id: &str) -> tutela_pdp::PathEntry {
    tutela_pdp::PathEntry::new(t.parse().unwrap(), id.parse().unwrap())
}

/// Every route of this API with a body that would succeed for an owner.
fn routes(w: &World) -> Vec<(Method, String, Option<Value>)> {
    let a = &w.a;
    let org = a.org.id.to_string();
    vec![
        (
            Method::GET,
            format!("/v1/admin/scopes?under=org:{org}"),
            None,
        ),
        (
            Method::POST,
            "/v1/admin/scopes".into(),
            Some(json!({"scope": {"type": "folder", "id": "f-x"}, "parent": scope(&a.project)})),
        ),
        (
            Method::POST,
            "/v1/admin/scopes/move".into(),
            Some(json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&a.project)})),
        ),
        (
            Method::POST,
            "/v1/admin/scopes/delete".into(),
            Some(json!({"scope": {"type": "folder", "id": "f-1"}})),
        ),
        (
            Method::PUT,
            "/v1/admin/scopes/private".into(),
            Some(json!({"scope": scope(&a.project), "private": true})),
        ),
        (
            Method::POST,
            "/v1/admin/assignments/list".into(),
            Some(json!({"scope": scope(&a.project)})),
        ),
        (
            Method::POST,
            "/v1/admin/assignments".into(),
            Some(json!({"subject": NEWCOMER, "role": "reader", "scope": scope(&a.project)})),
        ),
        (
            Method::PATCH,
            format!("/v1/admin/assignments/{}", a.assignment),
            Some(json!({"expires_at": null})),
        ),
        (
            Method::DELETE,
            format!("/v1/admin/assignments/{}", a.assignment),
            None,
        ),
        (Method::GET, format!("/v1/admin/groups?org={org}"), None),
        (
            Method::POST,
            "/v1/admin/groups".into(),
            Some(json!({"org": org, "key": "gx", "name": "X"})),
        ),
        (Method::DELETE, "/v1/admin/groups/team".into(), None),
        (Method::GET, "/v1/admin/groups/team/members".into(), None),
        (
            Method::POST,
            "/v1/admin/groups/team/members".into(),
            Some(json!({"member": NEWCOMER})),
        ),
        (
            Method::POST,
            "/v1/admin/groups/team/members/remove".into(),
            Some(json!({"member": NEWCOMER})),
        ),
        (Method::GET, "/v1/admin/roles".into(), None),
    ]
}

/// A group `team` in tenant A's org, and a folder f-1 under p-1.
async fn furnish(w: &World) {
    let admin = console(w, ADMIN, &w.a);
    let (status, v) = call(
        w,
        Method::POST,
        "/v1/admin/groups",
        Some(&admin),
        Some(&json!({"org": w.a.org.id.to_string(), "key": "team", "name": "Team"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = call(
        w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&admin),
        Some(&json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
}

#[tokio::test]
async fn tm01_every_route_refuses_the_tokens_the_admin_api_refuses() {
    let Some(mut w) = world().await else { return };
    furnish(&w).await;
    let tid = w.a.tid.clone();
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
            "a person with no key (a reader)",
            w.issuer.console(USER, &tid, 0),
        ),
        (
            "a viewer of the whole org",
            w.issuer.console(VIEWER, &tid, 0),
        ),
    ];
    let mut g = grpc(&w).await;
    for (what, t) in &denied {
        for (method, path, body) in routes(&w) {
            let (status, v) = call(&w, method.clone(), &path, Some(t), body.as_ref()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{what}: {method} {path}: {v}"
            );
            // A move is the write check's to refuse, for a caller that may
            // use the admin API at all.
            let code = problem(&v);
            assert!(
                code == "forbidden" || (path.ends_with("/move") && code == "move_refused"),
                "{what}: {method} {path}: {v}"
            );
        }
        // The same over gRPC.
        let calls: Vec<Result<tonic::Response<pb::JsonResult>, tonic::Status>> = vec![
            g.list_scopes(with_token(
                t,
                pb::ListScopesRequest {
                    under: format!("org:{}", w.a.org.id),
                    ..Default::default()
                },
            ))
            .await,
            g.put_scope(with_token(
                t,
                pb::PutScopeRequest {
                    scope: Some(path_entry(&entry("folder", "f-y"))),
                    parent: Some(path_entry(&w.a.project)),
                    private: None,
                },
            ))
            .await,
            g.move_scope(with_token(
                t,
                pb::MoveScopeRequest {
                    scope: Some(path_entry(&entry("folder", "f-1"))),
                    parent: Some(path_entry(&w.a.project)),
                    approved_by: vec![],
                },
            ))
            .await,
            g.delete_scope(with_token(
                t,
                pb::ScopeRequest {
                    scope: Some(path_entry(&entry("folder", "f-1"))),
                },
            ))
            .await,
            g.set_private(with_token(
                t,
                pb::SetPrivateRequest {
                    scope: Some(path_entry(&w.a.project)),
                    private: true,
                },
            ))
            .await,
            g.list_assignments(with_token(
                t,
                pb::ListAssignmentsRequest {
                    scope: Some(path_entry(&w.a.project)),
                    ..Default::default()
                },
            ))
            .await,
            g.assign(with_token(
                t,
                pb::AssignRequest {
                    subject: NEWCOMER.into(),
                    role: "reader".into(),
                    scope: Some(path_entry(&w.a.project)),
                    expires_at: String::new(),
                },
            ))
            .await,
            g.set_assignment_expiry(with_token(
                t,
                pb::SetAssignmentExpiryRequest {
                    id: w.a.assignment.to_string(),
                    expires_at: None,
                },
            ))
            .await,
            g.unassign(with_token(
                t,
                pb::AssignmentRequest {
                    id: w.a.assignment.to_string(),
                },
            ))
            .await,
            g.list_groups(with_token(t, pb::ListGroupsRequest::default()))
                .await,
            g.create_group(with_token(
                t,
                pb::CreateGroupRequest {
                    org: w.a.org.id.to_string(),
                    key: "gy".into(),
                    name: "Y".into(),
                },
            ))
            .await,
            g.delete_group(with_token(t, pb::GroupRequest { key: "team".into() }))
                .await,
            g.list_group_members(with_token(
                t,
                pb::ListGroupMembersRequest {
                    key: "team".into(),
                    ..Default::default()
                },
            ))
            .await,
            g.add_group_member(with_token(
                t,
                pb::GroupMemberRequest {
                    key: "team".into(),
                    member: NEWCOMER.into(),
                },
            ))
            .await,
            g.remove_group_member(with_token(
                t,
                pb::GroupMemberRequest {
                    key: "team".into(),
                    member: NEWCOMER.into(),
                },
            ))
            .await,
            g.list_roles(with_token(t, pb::ListRolesRequest::default()))
                .await,
        ];
        for (i, c) in calls.into_iter().enumerate() {
            let e = c.unwrap_err();
            assert_eq!(
                e.code(),
                Code::PermissionDenied,
                "{what}: gRPC call {i}: {e:?}"
            );
        }
    }
    // No token: 401 / UNAUTHENTICATED.
    for (method, path, body) in routes(&w) {
        let (status, _) = call(&w, method.clone(), &path, None, body.as_ref()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    let e = g
        .list_roles(tonic::Request::new(pb::ListRolesRequest::default()))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Unauthenticated);
    // Nothing changed: the reader's assignment is there, the group too.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&console(&w, ADMIN, &w.a)),
        Some(&json!({"scope": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(
        v["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["subject"] == USER),
        "{v}"
    );
    // Each refusal for want of a key was recorded, with who asked.
    let refused = audited(&mut w.d.owner, &w.a.key, "tutela_assignment:create").await;
    assert!(
        refused
            .iter()
            .any(|r| r["outcome"] == "denied" && r["actor"]["id"] == USER),
        "{refused:?}"
    );
    assert!(
        refused
            .iter()
            .any(|r| r["outcome"] == "denied" && r["actor"]["id"] == SA),
        "{refused:?}"
    );
    w.finish().await;
}

#[tokio::test]
async fn tm05_a_tenant_admin_reaches_its_own_tenant_only() {
    let Some(w) = world().await else { return };
    furnish(&w).await;
    let b_admin = console(&w, ADMIN, &w.b);
    let a_admin = console(&w, ADMIN, &w.a);
    // Tenant A's assignment, group and folder are not there for B: 404.
    for (method, path, body) in [
        (
            Method::DELETE,
            format!("/v1/admin/assignments/{}", w.a.assignment),
            None,
        ),
        (
            Method::PATCH,
            format!("/v1/admin/assignments/{}", w.a.assignment),
            Some(json!({"expires_at": null})),
        ),
        (Method::DELETE, "/v1/admin/groups/team".to_owned(), None),
        (
            Method::GET,
            "/v1/admin/groups/team/members".to_owned(),
            None,
        ),
        (
            Method::POST,
            "/v1/admin/groups/team/members".to_owned(),
            Some(json!({"member": NEWCOMER})),
        ),
        (
            Method::POST,
            "/v1/admin/scopes/delete".to_owned(),
            Some(json!({"scope": {"type": "folder", "id": "f-1"}})),
        ),
        (
            Method::POST,
            "/v1/admin/scopes/move".to_owned(),
            Some(json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&w.b.project)})),
        ),
        (
            Method::GET,
            "/v1/admin/scopes?under=folder:f-1".to_owned(),
            None,
        ),
    ] {
        let (status, v) = call(&w, method.clone(), &path, Some(&b_admin), body.as_ref()).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {v}");
    }
    // A's org is not B's: B's admin may not make a group or register a scope
    // in it, nor list it.
    let a_org = w.a.org.id.to_string();
    for (path, body) in [
        (
            "/v1/admin/groups",
            json!({"org": a_org, "key": "intruder", "name": "I"}),
        ),
        (
            "/v1/admin/scopes",
            json!({"scope": {"type": "project", "id": "p-9"}, "parent": scope(&w.a.org)}),
        ),
        (
            "/v1/admin/assignments",
            json!({"subject": NEWCOMER, "role": "reader", "scope": scope(&w.a.org)}),
        ),
    ] {
        let (status, v) = call(&w, Method::POST, path, Some(&b_admin), Some(&body)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {v}");
    }
    let (status, _) = call(
        &w,
        Method::GET,
        &format!("/v1/admin/scopes?under=org:{a_org}"),
        Some(&b_admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = call(
        &w,
        Method::GET,
        &format!("/v1/admin/groups?org={a_org}"),
        Some(&b_admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An assignment at project:p-1 by B's admin lands in B's own p-1.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&b_admin),
        Some(&json!({"subject": NEWCOMER, "role": "reader", "scope": scope(&w.b.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (_, a_list) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&a_admin),
        Some(&json!({"subject": NEWCOMER})),
    )
    .await;
    assert_eq!(a_list["assignments"], json!([]), "{a_list}");
    let (_, b_list) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&b_admin),
        Some(&json!({})),
    )
    .await;
    assert!(
        b_list["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["id"] != w.a.assignment.to_string()),
        "{b_list}"
    );
    let (_, groups) = call(&w, Method::GET, "/v1/admin/groups", Some(&b_admin), None).await;
    assert_eq!(groups["groups"], json!([]), "{groups}");
    // The same over gRPC.
    let mut g = grpc(&w).await;
    let e = g
        .unassign(with_token(
            &b_admin,
            pb::AssignmentRequest {
                id: w.a.assignment.to_string(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    let e = g
        .delete_group(with_token(
            &b_admin,
            pb::GroupRequest { key: "team".into() },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    let e = g
        .delete_scope(with_token(
            &b_admin,
            pb::ScopeRequest {
                scope: Some(path_entry(&entry("folder", "f-1"))),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{e:?}");
    // A's data is whole.
    let (_, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&a_admin),
        Some(&json!({"scope": scope(&w.a.project)})),
    )
    .await;
    assert!(
        v["assignments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == w.a.assignment.to_string()),
        "{v}"
    );
    w.finish().await;
}

#[tokio::test]
async fn tm08_nobody_grants_what_they_do_not_hold() {
    let Some(mut w) = world().await else { return };
    let keeper = console(&w, KEEPER, &w.a);
    let admin = console(&w, ADMIN, &w.a);
    let p1 = scope(&w.a.project);
    // The keeper may give what it holds: reader.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&keeper),
        Some(&json!({"subject": NEWCOMER, "role": "reader", "scope": p1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    assert_eq!(v["assignment"]["granted_by"], KEEPER);
    // Not approver (write on invoices, approve), nor owner, nor its own role
    // to a group... and never at the org, where it holds nothing.
    for role in ["approver", "owner", "keeper"] {
        let subject = if role == "keeper" { THIRD } else { OTHER };
        let (status, v) = call(
            &w,
            Method::POST,
            "/v1/admin/assignments",
            Some(&keeper),
            Some(&json!({"subject": subject, "role": role, "scope": p1})),
        )
        .await;
        if role == "keeper" {
            assert_eq!(status, StatusCode::OK, "its own role: {v}");
            continue;
        }
        assert_eq!(
            (status, problem(&v)),
            (StatusCode::FORBIDDEN, "not_held"),
            "{role}: {v}"
        );
        assert!(v["detail"].as_str().unwrap().contains("gain"), "{v}");
        assert!(
            !v["detail"].as_str().unwrap().contains("usr_"),
            "no principal in the detail: {v}"
        );
    }
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&keeper),
        Some(&json!({"subject": OTHER, "role": "reader", "scope": scope(&w.a.org)})),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "forbidden"),
        "{v}"
    );
    // The org admin may give approver.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": OTHER, "role": "approver", "scope": p1})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let approver_id = v["assignment"]["id"].as_str().unwrap().to_owned();
    assert!(v["rev"].as_u64().unwrap() > rev);

    // A removal that uncovers wider access is a grant too. NEWCOMER is in a
    // group that holds approver at the org; its direct reader at p-1 hides
    // that there. Taking the reader away gives NEWCOMER approver at p-1.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/groups",
        Some(&admin),
        Some(&json!({"org": w.a.org.id.to_string(), "key": "wide", "name": "Wide"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": "group:wide", "role": "approver", "scope": scope(&w.a.org)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/groups/wide/members",
        Some(&admin),
        Some(&json!({"member": NEWCOMER})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (_, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&admin),
        Some(&json!({"subject": NEWCOMER, "scope": p1})),
    )
    .await;
    let narrow = v["assignments"][0]["id"].as_str().unwrap().to_owned();
    let (status, v) = call(
        &w,
        Method::DELETE,
        &format!("/v1/admin/assignments/{narrow}"),
        Some(&keeper),
        None,
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "not_held"),
        "{v}"
    );
    // The refusal kept the assignment, and was recorded.
    let (_, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&admin),
        Some(&json!({"subject": NEWCOMER, "scope": p1})),
    )
    .await;
    assert_eq!(v["assignments"][0]["id"], narrow.as_str(), "{v}");
    let r = audited(&mut w.d.owner, &w.a.key, "tutela_assignment:delete").await;
    assert!(
        r.iter().any(|r| r["outcome"] == "denied"
            && r["reason"] == "not_held"
            && r["actor"]["id"] == KEEPER),
        "{r:?}"
    );
    // The org admin holds approver at p-1, so it may.
    let (status, v) = call(
        &w,
        Method::DELETE,
        &format!("/v1/admin/assignments/{narrow}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // A later end is a grant for the extra time: the keeper may end the
    // approver's assignment sooner, where it holds manage_access, but may
    // not make it last longer.
    let soon = time_in(3600);
    let later = time_in(7200);
    let (status, v) = call(
        &w,
        Method::PATCH,
        &format!("/v1/admin/assignments/{approver_id}"),
        Some(&admin),
        Some(&json!({"expires_at": later})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["assignment"]["expires_at"].is_string(), "{v}");
    let (status, v) = call(
        &w,
        Method::PATCH,
        &format!("/v1/admin/assignments/{approver_id}"),
        Some(&keeper),
        Some(&json!({"expires_at": soon})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "shorter: {v}");
    for longer in [json!({"expires_at": later}), json!({"expires_at": null})] {
        let (status, v) = call(
            &w,
            Method::PATCH,
            &format!("/v1/admin/assignments/{approver_id}"),
            Some(&keeper),
            Some(&longer),
        )
        .await;
        assert_eq!(
            (status, problem(&v)),
            (StatusCode::FORBIDDEN, "not_held"),
            "{longer}: {v}"
        );
    }
    // A time that has passed, and a body without the field, are 400.
    let (status, _) = call(
        &w,
        Method::PATCH,
        &format!("/v1/admin/assignments/{approver_id}"),
        Some(&admin),
        Some(&json!({"expires_at": "2001-01-01T00:00:00Z"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &w,
        Method::PATCH,
        &format!("/v1/admin/assignments/{approver_id}"),
        Some(&admin),
        Some(&json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A role the model lacks, or one a kind of subject may not hold.
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": OTHER, "role": "nobody", "scope": scope(&w.a.org)})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": "group:wide", "role": "owner", "scope": p1})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an admin role is never given to a group"
    );
    // One assignment per subject and scope.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": OTHER, "role": "reader", "scope": p1})),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::CONFLICT, "exists"),
        "{v}"
    );

    // A group's member gets what the group holds: the keeper may not add one.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/groups/wide/members",
        Some(&keeper),
        Some(&json!({"member": OTHER})),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "forbidden"),
        "no org:manage_access: {v}"
    );
    // Each change bumped the revision and went out as an event.
    let events = events_of(&mut w.d.owner, &w.a.key).await;
    let changed = events
        .iter()
        .filter(|e| e.event_type.to_string() == "tutela.permissions.changed.v1")
        .count();
    assert!(changed >= 6, "{changed}");
    let made = audited(&mut w.d.owner, &w.a.key, "tutela_assignment:create").await;
    assert!(
        made.iter().any(|r| r["outcome"] == "success"
            && r["actor"]["id"] == KEEPER
            && r["details"]["role"] == "reader"),
        "{made:?}"
    );
    w.finish().await;
}

fn time_in(secs: u64) -> String {
    let t = std::time::SystemTime::now() + std::time::Duration::from_secs(secs);
    let ms = t.duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
    tutela_contracts::timestamp::Timestamp::from_unix_millis(i64::try_from(ms).unwrap())
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_revoked_role_takes_effect_and_groups_nest_as_the_store_allows() {
    let Some(w) = world().await else { return };
    let admin = console(&w, ADMIN_SA, &w.a);
    let org = w.a.org.id.to_string();
    // Groups: made, listed with their member counts, a page at a time.
    for key in ["g1", "g2", "g3"] {
        let (status, v) = call(
            &w,
            Method::POST,
            "/v1/admin/groups",
            Some(&admin),
            Some(&json!({"org": org, "key": key, "name": key})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["members"], 0);
    }
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/groups",
        Some(&admin),
        Some(&json!({"org": org, "key": "g1", "name": "again"})),
    )
    .await;
    assert_eq!((status, problem(&v)), (StatusCode::CONFLICT, "exists"));
    for (g, m) in [("g1", "group:g2"), ("g2", "group:g3"), ("g3", NEWCOMER)] {
        let (status, v) = call(
            &w,
            Method::POST,
            &format!("/v1/admin/groups/{g}/members"),
            Some(&admin),
            Some(&json!({"member": m})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
    }
    // A cycle is refused by the store's load checks: 409.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/groups/g3/members",
        Some(&admin),
        Some(&json!({"member": "group:g1"})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    let (_, page1) = call(
        &w,
        Method::GET,
        "/v1/admin/groups?limit=2",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(page1["groups"].as_array().unwrap().len(), 2, "{page1}");
    let after = page1["next_after"].as_str().unwrap();
    let (_, page2) = call(
        &w,
        Method::GET,
        &format!("/v1/admin/groups?limit=2&after={after}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(page2["groups"][0]["key"], "g3", "{page2}");
    assert_eq!(page2["groups"][0]["members"], 1);
    let (_, members) = call(
        &w,
        Method::GET,
        "/v1/admin/groups/g1/members",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(members["members"], json!(["group:g2"]), "{members}");

    // A role given to g1 reaches NEWCOMER through g2 and g3; the check API
    // sees it at the new revision, and stops seeing it once it is removed.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments",
        Some(&admin),
        Some(&json!({"subject": "group:g1", "role": "approver", "scope": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    let id = v["assignment"]["id"].as_str().unwrap().to_owned();
    let newcomer = w.issuer.token(NEWCOMER, &w.a.tid, rev);
    let ask = |rev: u64| {
        let mut a = common::ask(NEWCOMER, "invoice:approve", &w.a);
        a["context"] = json!({"at_least_revision": rev});
        a
    };
    let (status, v) = call(
        &w,
        Method::POST,
        "/access/v1/evaluation",
        Some(&newcomer),
        Some(&ask(rev)),
    )
    .await;
    assert_eq!(
        (status, v["decision"].as_bool()),
        (StatusCode::OK, Some(true)),
        "{v}"
    );
    let (status, v) = call(
        &w,
        Method::DELETE,
        &format!("/v1/admin/assignments/{id}"),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    let (_, v) = call(
        &w,
        Method::POST,
        "/access/v1/evaluation",
        Some(&w.issuer.token(NEWCOMER, &w.a.tid, rev)),
        Some(&ask(rev)),
    )
    .await;
    assert_eq!(v["decision"], false, "{v}");
    // Removing a member, then deleting the groups.
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/groups/g3/members/remove",
        Some(&admin),
        Some(&json!({"member": NEWCOMER})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/groups/g3/members/remove",
        Some(&admin),
        Some(&json!({"member": NEWCOMER})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for g in ["g1", "g2", "g3"] {
        let (status, v) = call(
            &w,
            Method::DELETE,
            &format!("/v1/admin/groups/{g}"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
    }

    // Assignments: a page at a time, by id.
    for who in [NEWCOMER, OTHER] {
        let (status, v) = call(
            &w,
            Method::POST,
            "/v1/admin/assignments",
            Some(&admin),
            Some(&json!({"subject": who, "role": "reader", "scope": scope(&w.a.org)})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
    }
    let (_, all) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&admin),
        Some(&json!({})),
    )
    .await;
    let n = all["assignments"].as_array().unwrap().len();
    let (_, first) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&admin),
        Some(&json!({"limit": 2})),
    )
    .await;
    let mut seen: Vec<Value> = first["assignments"].as_array().unwrap().clone();
    let mut after = first["next_after"].clone();
    while let Some(a) = after.as_str() {
        let (_, next) = call(
            &w,
            Method::POST,
            "/v1/admin/assignments/list",
            Some(&admin),
            Some(&json!({"limit": 2, "after": a})),
        )
        .await;
        seen.extend(next["assignments"].as_array().unwrap().iter().cloned());
        after = next["next_after"].clone();
    }
    assert_eq!(seen.len(), n);
    // The roles and types, for the permission matrix.
    let (status, roles) = call(&w, Method::GET, "/v1/admin/roles", Some(&admin), None).await;
    assert_eq!(status, StatusCode::OK, "{roles}");
    let approver = roles["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "approver")
        .unwrap();
    assert_eq!(approver["levels"]["invoice"], "write", "{approver}");
    assert!(
        approver["grants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g == "invoice:approve")
    );
    let invoice = roles["types"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "invoice")
        .unwrap();
    assert!(
        invoice["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "amount" && f["sensitivity"] == "confidential"),
        "{invoice}"
    );
    // A project's owner sees the roles of its project, and its members.
    let owner = console(&w, PROJECT_OWNER, &w.a);
    let (status, _) = call(
        &w,
        Method::GET,
        &format!("/v1/admin/roles?scope=project:{}", w.a.project.id),
        Some(&owner),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&w, Method::GET, "/v1/admin/roles", Some(&owner), None).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the whole tenant needs read_audit at every org"
    );
    w.finish().await;
}

#[tokio::test]
async fn a_move_goes_through_write_check_and_its_boundary_rules() {
    let Some(mut w) = world().await else { return };
    let admin = console(&w, ADMIN, &w.a);
    let sa = console(&w, ADMIN_SA, &w.a);
    let owner = console(&w, PROJECT_OWNER, &w.a);
    // A second project, and a folder in each, registered by the services
    // that make them.
    let p2 = entry("project", "p-2");
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&sa),
        Some(&json!({"scope": scope(&p2), "parent": scope(&w.a.org)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["scope"]["ancestors"], json!([scope(&w.a.org)]), "{v}");
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&owner),
        Some(&json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the project's owner writes in it: {v}"
    );
    assert_eq!(
        v["scope"]["ancestors"],
        json!([scope(&w.a.project), scope(&w.a.org)])
    );
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&owner),
        Some(&json!({"scope": {"type": "folder", "id": "f-2"}, "parent": scope(&p2)})),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "forbidden"),
        "not its project: {v}"
    );
    // The model's tree: a project never sits under a folder; an invoice is
    // not a scope.
    let (status, _) = call(&w, Method::POST, "/v1/admin/scopes", Some(&admin), Some(&json!({"scope": {"type": "project", "id": "p-x"}, "parent": {"type": "folder", "id": "f-1"}}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&admin),
        Some(&json!({"scope": {"type": "invoice", "id": "i-x"}, "parent": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes",
        Some(&admin),
        Some(&json!({"scope": scope(&p2), "parent": scope(&w.a.org)})),
    )
    .await;
    assert_eq!((status, problem(&v)), (StatusCode::CONFLICT, "exists"));

    // The project's owner may not move f-1 into p-2, where it may not write.
    let mv = json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&p2)});
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/move",
        Some(&owner),
        Some(&mv),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "move_refused"),
        "{v}"
    );
    // A person may not name who approved.
    let with_approver = json!({"scope": {"type": "folder", "id": "f-1"}, "parent": scope(&p2), "approved_by": [ADMIN]});
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/move",
        Some(&admin),
        Some(&with_approver),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A rule that blocks moves out of p-1 holds even for the org's owner.
    let (status, v) = call(
        &w,
        Method::PUT,
        "/v1/admin/boundaries",
        Some(&admin),
        Some(&json!({"scope": scope(&w.a.project), "moves_out": "none"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/move",
        Some(&admin),
        Some(&mv),
    )
    .await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "move_refused"),
        "{v}"
    );
    let (status, v) = call(
        &w,
        Method::PUT,
        "/v1/admin/boundaries",
        Some(&admin),
        Some(&json!({"scope": scope(&w.a.project)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // The org's owner may: the scope and its path move in one revision.
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/move",
        Some(&admin),
        Some(&mv),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(
        v["scope"]["ancestors"],
        json!([scope(&p2), scope(&w.a.org)]),
        "{v}"
    );
    let (_, listed) = call(
        &w,
        Method::GET,
        "/v1/admin/scopes?under=project:p-2",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        listed["scopes"][0]["scope"],
        json!({"type": "folder", "id": "f-1"}),
        "{listed}"
    );
    let (_, listed) = call(
        &w,
        Method::GET,
        &format!("/v1/admin/scopes?under=project:{}", w.a.project.id),
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(listed["scopes"], json!([]), "{listed}");
    // Each verdict was recorded with both paths.
    let moves = audited(&mut w.d.owner, &w.a.key, "tutela_scope:move").await;
    assert!(
        moves
            .iter()
            .any(|r| r["outcome"] == "denied" && r["actor"]["id"] == PROJECT_OWNER),
        "{moves:?}"
    );
    let ok = moves.iter().find(|r| r["outcome"] == "success").unwrap();
    assert_eq!(
        ok["details"]["to"],
        json!(["project:p-2".to_owned(), format!("org:{}", w.a.org.id)])
    );

    // The private flag needs manage_boundaries on the scope.
    let (status, _) = call(
        &w,
        Method::PUT,
        "/v1/admin/scopes/private",
        Some(&console(&w, KEEPER, &w.a)),
        Some(&json!({"scope": scope(&w.a.project), "private": true})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, v) = call(
        &w,
        Method::PUT,
        "/v1/admin/scopes/private",
        Some(&owner),
        Some(&json!({"scope": scope(&w.a.project), "private": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    // Deleting needs delete on the scope; the project's owner does not hold
    // it in p-2.
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/delete",
        Some(&owner),
        Some(&json!({"scope": {"type": "folder", "id": "f-1"}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, v) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/delete",
        Some(&sa),
        Some(&json!({"scope": {"type": "folder", "id": "f-1"}})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let (status, _) = call(
        &w,
        Method::POST,
        "/v1/admin/scopes/delete",
        Some(&sa),
        Some(&json!({"scope": {"type": "folder", "id": "f-1"}})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Letting inheritance into p-1 again gives the org's service account its
    // owner role there: the org's owner holds that, the keeper would not.
    let (status, v) = call(
        &w,
        Method::PUT,
        "/v1/admin/scopes/private",
        Some(&admin),
        Some(&json!({"scope": scope(&w.a.project), "private": false})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{v}");

    // The same over gRPC.
    let mut g = grpc(&w).await;
    let r = g
        .put_scope(with_token(
            &sa,
            pb::PutScopeRequest {
                scope: Some(path_entry(&entry("folder", "f-3"))),
                parent: Some(path_entry(&p2)),
                private: Some(false),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    assert_eq!(v["scope"]["private"], false, "{v}");
    let e = g
        .move_scope(with_token(
            &owner,
            pb::MoveScopeRequest {
                scope: Some(path_entry(&entry("folder", "f-3"))),
                parent: Some(path_entry(&w.a.project)),
                approved_by: vec![],
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");
    assert!(e.message().starts_with("move_refused"), "{e:?}");
    let r = g
        .move_scope(with_token(
            &sa,
            pb::MoveScopeRequest {
                scope: Some(path_entry(&entry("folder", "f-3"))),
                parent: Some(path_entry(&w.a.project)),
                approved_by: vec![],
            },
        ))
        .await;
    assert!(r.is_ok(), "{r:?}");
    let r = g
        .list_scopes(with_token(
            &admin,
            pb::ListScopesRequest {
                under: format!("org:{}", w.a.org.id),
                after: String::new(),
                limit: 0,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    assert!(v["scopes"].as_array().unwrap().len() >= 3, "{v}");
    w.finish().await;
}

#[tokio::test]
async fn the_grpc_methods_answer_what_the_routes_answer() {
    let Some(w) = world().await else { return };
    let admin = console(&w, ADMIN, &w.a);
    let mut g = grpc(&w).await;
    let r = g
        .create_group(with_token(
            &admin,
            pb::CreateGroupRequest {
                org: w.a.org.id.to_string(),
                key: "crew".into(),
                name: "Crew".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    assert_eq!(v["key"], "crew");
    g.add_group_member(with_token(
        &admin,
        pb::GroupMemberRequest {
            key: "crew".into(),
            member: NEWCOMER.into(),
        },
    ))
    .await
    .unwrap();
    let r = g
        .list_group_members(with_token(
            &admin,
            pb::ListGroupMembersRequest {
                key: "crew".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let (_, http_members) = call(
        &w,
        Method::GET,
        "/v1/admin/groups/crew/members",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&r.result_json).unwrap(),
        http_members
    );
    let r = g
        .assign(with_token(
            &admin,
            pb::AssignRequest {
                subject: "group:crew".into(),
                role: "reader".into(),
                scope: Some(path_entry(&w.a.project)),
                expires_at: time_in(600),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    let id = v["assignment"]["id"].as_str().unwrap().to_owned();
    assert!(v["assignment"]["expires_at"].is_string());
    let r = g
        .set_assignment_expiry(with_token(
            &admin,
            pb::SetAssignmentExpiryRequest {
                id: id.clone(),
                expires_at: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let v: Value = serde_json::from_str(&r.result_json).unwrap();
    assert!(v["assignment"]["expires_at"].is_null(), "permanent: {v}");
    let r = g
        .list_assignments(with_token(
            &admin,
            pb::ListAssignmentsRequest {
                subject: "group:crew".into(),
                ..Default::default()
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let (_, http_list) = call(
        &w,
        Method::POST,
        "/v1/admin/assignments/list",
        Some(&admin),
        Some(&json!({"subject": "group:crew"})),
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&r.result_json).unwrap(),
        http_list
    );
    g.unassign(with_token(&admin, pb::AssignmentRequest { id }))
        .await
        .unwrap();
    let r = g
        .list_groups(with_token(&admin, pb::ListGroupsRequest::default()))
        .await
        .unwrap()
        .into_inner();
    let (_, http_groups) = call(&w, Method::GET, "/v1/admin/groups", Some(&admin), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&r.result_json).unwrap(),
        http_groups
    );
    g.remove_group_member(with_token(
        &admin,
        pb::GroupMemberRequest {
            key: "crew".into(),
            member: NEWCOMER.into(),
        },
    ))
    .await
    .unwrap();
    g.delete_group(with_token(&admin, pb::GroupRequest { key: "crew".into() }))
        .await
        .unwrap();
    let r = g
        .list_roles(with_token(&admin, pb::ListRolesRequest::default()))
        .await
        .unwrap()
        .into_inner();
    let (_, http_roles) = call(&w, Method::GET, "/v1/admin/roles", Some(&admin), None).await;
    assert_eq!(
        serde_json::from_str::<Value>(&r.result_json).unwrap(),
        http_roles
    );
    // A refusal is the problem's code in the message.
    let keeper = console(&w, KEEPER, &w.a);
    let e = g
        .assign(with_token(
            &keeper,
            pb::AssignRequest {
                subject: OTHER.into(),
                role: "approver".into(),
                scope: Some(path_entry(&w.a.project)),
                expires_at: String::new(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    assert!(e.message().starts_with("not_held"), "{e:?}");
    w.finish().await;
}
