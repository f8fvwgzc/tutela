//! The lifecycle of tenants, orgs and people, through the real auth layer
//! on a real Postgres (ADR-0041, CONTRACTS.md 7.13.5): the operator makes a
//! tenant; its owner names it, makes, deletes and restores orgs, deletes
//! people and soft-deletes the tenant; the purge after the grace keeps the
//! audit chain.
#![cfg(test)]

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{Value, json};
use tonic::Code;
use tutela_contracts::tenant::TenantKey;
use tutela_pdp::model::RoleKey;
use tutela_pdp::{PathEntry, Subject};
use tutela_store::tokio_postgres::Client;
use tutelad::admin::grpc::pb;
use tutelad::admin::grpc::pb::admin_client::AdminClient;
use tutelad::api::AppState;
use tutelad::lifecycle::{NewTenant, create_tenant};

use common::{ISS, Issuer, MANIFEST, Running, SA, STEP_UP, TestDb, USER, http};

const ADMIN: &str = "user:usr_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b1";
const ADMIN_SA: &str = "sa:sa_0193a1b2-c3d4-7a11-8b22-3c4d5e6f70b2";
const KC: &str = "https://kc.example.test/realms/acme";

struct Made {
    key: TenantKey,
    tid: String,
    org: PathEntry,
    project: PathEntry,
}

struct L {
    d: TestDb,
    issuer: Issuer,
    a: Made,
    b: Made,
    st: AppState,
    s: Running,
}

/// A tenant made the operator's way, under the test issuer, with a project
/// `p-1` where USER reads.
async fn made(owner: &mut Client) -> Made {
    let new = NewTenant {
        name: Some("Acme".into()),
        org_name: Some("Head office".into()),
        admins: vec![ADMIN.parse().unwrap(), ADMIN_SA.parse().unwrap()],
        upstream_admins: Vec::new(),
    };
    let c = create_tenant(owner, &ISS.parse().unwrap(), &new)
        .await
        .unwrap();
    let org = PathEntry::org(&c.org).unwrap();
    let project = PathEntry::new("project".parse().unwrap(), "p-1".parse().unwrap());
    let tx = owner.transaction().await.unwrap();
    tutela_store::put_scope(&tx, &c.key, &project, std::slice::from_ref(&org), false)
        .await
        .unwrap();
    tutela_store::assign(
        &tx,
        &c.key,
        &Subject::Principal(USER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &project,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Made {
        tid: c.key.tid.to_string(),
        key: c.key,
        org,
        project,
    }
}

async fn l() -> Option<L> {
    let mut d = common::migrated().await?;
    common::publish(&mut d.owner, MANIFEST, None).await;
    let a = made(&mut d.owner).await;
    let b = made(&mut d.owner).await;
    let issuer = Issuer::new();
    let cfg = common::config(
        &d.service_url,
        common::trust(&[a.tid.clone(), b.tid.clone()]),
    );
    let st = common::state(&cfg, &issuer);
    let s = common::start(&cfg, st.clone()).await;
    Some(L {
        d,
        issuer,
        a,
        b,
        st,
        s,
    })
}

impl L {
    async fn finish(self) {
        self.s.stop().await.unwrap();
        self.d.finish().await;
    }

    fn console(&self, who: &str, m: &Made) -> String {
        self.issuer.console(who, &m.tid, 0)
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut r = http()
            .request(method, self.s.api_url(path))
            .bearer_auth(token);
        if let Some(b) = body {
            r = r.json(b);
        }
        let res = r.send().await.unwrap();
        let status = res.status();
        let text = res.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn post(&self, path: &str, token: &str, body: &Value) -> (StatusCode, Value) {
        self.call(reqwest::Method::POST, path, token, Some(body))
            .await
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, Value) {
        self.call(reqwest::Method::GET, path, token, None).await
    }

    /// May `who` read an invoice under `scope` of `m`, at `rev` or later?
    async fn reads(
        &self,
        m: &Made,
        who: &str,
        scope: &PathEntry,
        org: &PathEntry,
        rev: u64,
    ) -> bool {
        let q = json!({
            "subject": {"type": "user", "id": who},
            "action": {"name": "invoice:read"},
            "resource": {"type": "invoice", "id": "inv-1", "properties": {
                "path": [{"type": scope.type_name.to_string(), "id": scope.id.to_string()},
                         {"type": "org", "id": org.id.to_string()}], "attrs": {}}},
            "context": {"at_least_revision": rev},
        });
        let (status, v) = self
            .post(
                "/access/v1/evaluation",
                &self.issuer.token(SA, &m.tid, 0),
                &q,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        v["decision"].as_bool().unwrap()
    }

    async fn grpc(&self) -> AdminClient<tonic::transport::Channel> {
        let channel = tonic::transport::Endpoint::from_shared(self.s.api_url(""))
            .unwrap()
            .connect()
            .await
            .unwrap();
        AdminClient::new(channel)
    }
}

fn with_token<T>(token: &str, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

fn problem(v: &Value) -> &str {
    v["type"]
        .as_str()
        .and_then(|t| t.strip_prefix("urn:tutela:problem:"))
        .unwrap_or("")
}

async fn records(owner: &mut Client, key: &TenantKey, action: &str) -> Vec<Value> {
    common::audited(owner, key, action).await
}

async fn deployment_records(owner: &mut Client, action: &str) -> Vec<Value> {
    let tx = owner.transaction().await.unwrap();
    let rows = tutela_store::deployment_audit_records(&tx, 0, 1000)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    rows.iter()
        .map(|r| serde_json::from_str::<Value>(&r.body).unwrap())
        .filter(|r| r["action"] == action)
        .collect()
}

async fn event_types(owner: &mut Client, key: &TenantKey) -> Vec<(String, Value)> {
    common::events_of(owner, key)
        .await
        .into_iter()
        .map(|e| (e.event_type.to_string(), Value::Object(e.data)))
        .collect()
}

/// Puts the purge time of `what` (`tenant` or `org`) in the past, as time
/// passing would, as a superuser.
async fn age(d: &TestDb, table: &str, column: &str, id: &str) {
    let su = d.superuser().await;
    let n = su
        .execute(
            &format!(
                "UPDATE tutela.{table} SET purge_after = now() - interval '1 second' WHERE {column} = $1"
            ),
            &[&id],
        )
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn the_operator_makes_a_tenant_with_its_first_org_and_owners() {
    let Some(mut d) = common::migrated().await else {
        return;
    };
    common::publish(&mut d.owner, MANIFEST, None).await;
    let own: tutela_contracts::tenant::Issuer = ISS.parse().unwrap();
    // A tenant needs an owner; a key or an agent is not one.
    assert!(
        create_tenant(&mut d.owner, &own, &NewTenant::default())
            .await
            .is_err()
    );
    let agent = NewTenant {
        admins: vec![common::AGENT.parse().unwrap()],
        ..NewTenant::default()
    };
    assert!(create_tenant(&mut d.owner, &own, &agent).await.is_err());

    let c = create_tenant(
        &mut d.owner,
        &own,
        &NewTenant {
            name: Some("Acme".into()),
            org_name: None,
            admins: vec![ADMIN_SA.parse().unwrap()],
            upstream_admins: vec![(KC.parse().unwrap(), "alice".into())],
        },
    )
    .await
    .unwrap();
    assert_eq!(c.owners.len(), 2);
    let person = c.owners[1].clone();
    assert!(person.to_string().starts_with("user:usr_"));
    let tx = d.owner.transaction().await.unwrap();
    let info = tutela_store::tenant_info(&tx, &c.key).await.unwrap();
    let bundle = tutela_store::load(&tx, &c.key).await.unwrap();
    // The upstream account is linked: the same (iss, sub) finds the person.
    let (again, created) = tutela_store::provision_user(&tx, &c.key, &KC.parse().unwrap(), "alice")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(info.name.as_deref(), Some("Acme"));
    assert!(bundle.data.orgs.contains(&c.org));
    assert_eq!(bundle.data.bindings.len(), 2);
    assert!(
        bundle
            .data
            .bindings
            .iter()
            .all(|b| b.role.as_str() == "owner")
    );
    assert_eq!((again.principal, created), (person, false));
    // Recorded in its own chain and the deployment's, by tutelad itself.
    let r = records(&mut d.owner, &c.key, "tutela_tenant:create").await;
    assert_eq!(r[0]["actor"]["id"], tutelad::audit::SYSTEM);
    assert_eq!(
        records(&mut d.owner, &c.key, "tutela_org:owner")
            .await
            .len(),
        2
    );
    let dep = deployment_records(&mut d.owner, "tutela_tenant:create").await;
    assert_eq!(dep[0]["details"]["tid"], c.key.tid.to_string());
    let types: Vec<String> = event_types(&mut d.owner, &c.key)
        .await
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    assert!(
        types.contains(&"tutela.org.created.v1".to_owned()),
        "{types:?}"
    );
    d.finish().await;
}

#[tokio::test]
async fn tm14_the_service_role_changes_only_the_directory_row_of_its_tenant() {
    let Some(l) = l().await else { return };
    let svc = common::connect(&l.d.service_url).await;
    let mut svc = svc;
    let tx = svc.transaction().await.unwrap();
    tutela_store::enter(&tx, &l.a.key).await.unwrap();
    let n = tx
        .execute(
            "UPDATE tutela.tenant SET name = 'x' WHERE tenant_id = $1",
            &[&l.b.tid],
        )
        .await
        .unwrap();
    assert_eq!(n, 0, "a row of another tenant was changed");
    let n = tx
        .execute("UPDATE tutela.tenant SET name = 'mine'", &[])
        .await
        .unwrap();
    assert_eq!(n, 1, "only its own row");
    tx.rollback().await.unwrap();
    for sql in [
        "INSERT INTO tutela.tenant (tenant_id, iss) VALUES ('ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', 'https://x.test')",
        "DELETE FROM tutela.tenant",
        "UPDATE tutela.tenant SET iss = 'https://x.test'",
    ] {
        let e = svc.batch_execute(sql).await.unwrap_err();
        assert_eq!(e.code().unwrap().code(), "42501", "{sql}");
    }
    // Readiness holds: the role isolates tenants.
    tutela_store::check_isolation(&svc).await.unwrap();
    l.finish().await;
}

#[tokio::test]
async fn orgs_are_made_renamed_deleted_restored_and_purged() {
    let Some(mut l) = l().await else { return };
    let admin = l.console(ADMIN, &l.a);

    // Making an org takes every admin key at every org; its maker owns it.
    let (status, _) = l
        .post(
            "/v1/admin/orgs",
            &l.console(USER, &l.a),
            &json!({"name": "Branch"}),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, v) = l
        .post("/v1/admin/orgs", &admin, &json!({"name": "Branch"}))
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "Branch");
    let org2 = v["org"].as_str().unwrap().to_owned();
    let org2_entry = PathEntry::new("org".parse().unwrap(), org2.parse().unwrap());
    // The maker is still an admin at every org, the new one included.
    let (status, v) = l.get("/v1/admin/orgs", &admin).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert_eq!(v["orgs"].as_array().unwrap().len(), 2);

    // Renamed by an admin of that org; a reader may not; another tenant's
    // admin does not find it.
    let path = format!("/v1/admin/orgs/{org2}");
    let (status, _) = l
        .call(
            reqwest::Method::PATCH,
            &path,
            &l.console(USER, &l.a),
            Some(&json!({"name": "X"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = l
        .call(
            reqwest::Method::PATCH,
            &path,
            &l.console(ADMIN, &l.b),
            Some(&json!({"name": "X"})),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = l
        .call(
            reqwest::Method::DELETE,
            &path,
            &l.console(ADMIN, &l.b),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, v) = l
        .call(
            reqwest::Method::PATCH,
            &path,
            &admin,
            Some(&json!({"name": "Branch 2"})),
        )
        .await;
    assert_eq!(
        (status, v["name"].as_str()),
        (StatusCode::OK, Some("Branch 2"))
    );

    // A project of the new org, where USER reads.
    let p2 = PathEntry::new("project".parse().unwrap(), "p-2".parse().unwrap());
    let tx = l.d.owner.transaction().await.unwrap();
    tutela_store::put_scope(&tx, &l.a.key, &p2, std::slice::from_ref(&org2_entry), false)
        .await
        .unwrap();
    let (_, rev) = tutela_store::assign(
        &tx,
        &l.a.key,
        &Subject::Principal(USER.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &p2,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(l.reads(&l.a, USER, &p2, &org2_entry, rev).await);

    // Deleted: out of every decision in the same revision; the last org stays.
    let (status, v) = l.call(reqwest::Method::DELETE, &path, &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    assert!(v["purge_after"].is_string());
    assert!(!l.reads(&l.a, USER, &p2, &org2_entry, rev).await);
    assert!(l.reads(&l.a, USER, &l.a.project, &l.a.org, rev).await);
    let first = format!("/v1/admin/orgs/{}", l.a.org.id);
    let (status, v) = l.call(reqwest::Method::DELETE, &first, &admin, None).await;
    assert_eq!((status, problem(&v)), (StatusCode::CONFLICT, "last_org"));
    // Nothing new is written under a deleted org.
    let tx = l.d.owner.transaction().await.unwrap();
    let e = tutela_store::assign(
        &tx,
        &l.a.key,
        &Subject::Principal(ADMIN.parse().unwrap()),
        &RoleKey::parse("reader").unwrap(),
        &p2,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(e.kind(), tutela_store::StoreErrorKind::NotFound);
    drop(tx);

    // Restored over gRPC: back in the decisions.
    let mut g = l.grpc().await;
    let o = g
        .restore_org(with_token(&admin, pb::OrgRequest { org: org2.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert!(o.deleted_at.is_empty());
    assert!(l.reads(&l.a, USER, &p2, &org2_entry, o.rev).await);

    // Deleted again and purged after the grace: its data goes, its row and
    // the audit chain stay.
    let o = g
        .delete_org(with_token(&admin, pb::OrgRequest { org: org2.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert!(!o.purge_after.is_empty());
    age(&l.d, "org", "org_id", &org2).await;
    let p = tutelad::expiry::purge(&l.st.db, &l.st.metrics, &ISS.parse().unwrap())
        .await
        .unwrap();
    assert_eq!((p.orgs, p.failed), (1, 0));
    let su = l.d.superuser().await;
    let left: i64 = su
        .query_one(
            "SELECT (SELECT count(*) FROM tutela.role_assignment WHERE scope_id = 'p-2') \
             + (SELECT count(*) FROM tutela.scope_path WHERE scope_id = 'p-2')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0);
    let (_, v) = l.get("/v1/admin/orgs", &admin).await;
    let gone = v["orgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["org"] == org2.as_str())
        .unwrap();
    assert!(gone["purged_at"].is_string(), "{gone}");
    let (status, _) = l
        .post(
            &format!("/v1/admin/orgs/{org2}/restore"),
            &admin,
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Events and records, with who asked.
    let events = event_types(&mut l.d.owner, &l.a.key).await;
    for t in [
        "tutela.org.created.v1",
        "tutela.org.updated.v1",
        "tutela.org.deleted.v1",
    ] {
        assert!(events.iter().any(|(x, _)| x == t), "{t}");
    }
    let deleted = events
        .iter()
        .find(|(t, d)| t == "tutela.org.deleted.v1" && d["org"] == org2.as_str())
        .unwrap();
    assert!(deleted.1["purge_after"].is_string());
    for (action, by) in [
        ("tutela_org:create", ADMIN),
        ("tutela_org:update", ADMIN),
        ("tutela_org:delete", ADMIN),
        ("tutela_org:restore", ADMIN),
        ("tutela_org:purge", tutelad::audit::SYSTEM),
    ] {
        let r = records(&mut l.d.owner, &l.a.key, action).await;
        assert!(
            r.iter()
                .any(|r| r["outcome"] == "success" && r["actor"]["id"] == by),
            "{action}: {r:?}"
        );
    }
    l.finish().await;
}

#[tokio::test]
async fn deleting_a_person_removes_its_access_and_its_tokens() {
    let Some(mut l) = l().await else { return };
    let admin = l.console(ADMIN, &l.a);
    let token = l.issuer.token(USER, &l.a.tid, 0);
    assert!(l.reads(&l.a, USER, &l.a.project, &l.a.org, 0).await);
    // A person linked to an upstream account.
    let tx = l.d.owner.transaction().await.unwrap();
    let (alice, _) = tutela_store::provision_user(&tx, &l.a.key, &KC.parse().unwrap(), "alice")
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Refused without the key; B's admin deleting "USER" is a row of B only.
    let body = json!({"principal": USER});
    let (status, _) = l
        .post("/v1/admin/users/delete", &l.console(SA, &l.a), &body)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = l
        .post("/v1/admin/users/delete", &l.console(ADMIN, &l.b), &body)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(l.reads(&l.a, USER, &l.a.project, &l.a.org, 0).await);
    let (status, _) = l
        .post("/v1/admin/users/delete", &admin, &json!({"principal": SA}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, v) = l.post("/v1/admin/users/delete", &admin, &body).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    let rev = v["rev"].as_u64().unwrap();
    assert!(!l.reads(&l.a, USER, &l.a.project, &l.a.org, rev).await);
    let start = std::time::Instant::now();
    while l.get("/v1/whoami", &token).await.0 != StatusCode::UNAUTHORIZED {
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "the deleted person's token works"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Never enabled again; deleting twice is 404.
    let (status, _) = l
        .post(
            "/v1/admin/principals/disabled",
            &admin,
            &json!({"principal": USER, "disabled": false}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = l.post("/v1/admin/users/delete", &admin, &body).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Over gRPC; the upstream link goes, so the same account signing in again
    // is a new person who holds nothing.
    let mut g = l.grpc().await;
    let s = g
        .delete_user(with_token(
            &admin,
            pb::PrincipalRequest {
                principal: alice.principal.to_string(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(s.disabled);
    let tx = l.d.owner.transaction().await.unwrap();
    let (again, created) =
        tutela_store::provision_user(&tx, &l.a.key, &KC.parse().unwrap(), "alice")
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert!(created);
    assert_ne!(again.principal, alice.principal);

    let events = event_types(&mut l.d.owner, &l.a.key).await;
    assert!(
        events
            .iter()
            .any(|(t, d)| t == "tutela.user.deleted.v1" && d["user"] == USER)
    );
    assert!(
        events
            .iter()
            .any(|(t, d)| t == "tutela.principal.disabled.v1" && d["principal"] == USER)
    );
    let r: Vec<Value> = records(&mut l.d.owner, &l.a.key, "tutela_principal:delete")
        .await
        .into_iter()
        .filter(|r| r["outcome"] == "success")
        .collect();
    assert_eq!(r[0]["actor"]["id"], ADMIN);
    assert_eq!(r[0]["details"]["principal"], USER);
    assert!(
        records(&mut l.d.owner, &l.a.key, "tutela_principal:delete")
            .await
            .iter()
            .any(|r| r["outcome"] == "denied" && r["actor"]["id"] == SA)
    );
    l.finish().await;
}

/// Reads an event stream until it ends, at most `wait`. `true` if it ended.
async fn ends_within(res: &mut reqwest::Response, wait: Duration) -> bool {
    let until = tokio::time::Instant::now() + wait;
    loop {
        let left = until.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, res.chunk()).await {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None) | Err(_)) => return true,
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn a_soft_deleted_tenant_answers_nothing_and_keeps_its_audit_chain() {
    let Some(mut l) = l().await else { return };
    let admin = l.console(ADMIN, &l.a);
    let service = l.issuer.token(SA, &l.a.tid, 0);
    let mut stream = http()
        .get(l.s.api_url("/v1/events"))
        .bearer_auth(&service)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), StatusCode::OK);

    // Named, then refused to a principal without every key, then deleted.
    let (status, v) = l
        .call(
            reqwest::Method::PATCH,
            "/v1/admin/tenant",
            &admin,
            Some(&json!({"name": "Acme 2"})),
        )
        .await;
    assert_eq!(
        (status, v["name"].as_str()),
        (StatusCode::OK, Some("Acme 2"))
    );
    for t in [
        l.console(USER, &l.a),
        l.issuer.token(ADMIN, &l.a.tid, 0),
        service.clone(),
    ] {
        let (status, _) = l
            .call(reqwest::Method::DELETE, "/v1/admin/tenant", &t, None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, v) = l
        .call(reqwest::Method::DELETE, "/v1/admin/tenant", &admin, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{v}");
    assert!(v["purge_after"].is_string());

    // It answers nothing: at once where a request reads the database, within
    // the revision lease where a replica answers from memory.
    let (status, v) = l.get("/v1/whoami", &service).await;
    assert_eq!(
        (status, problem(&v)),
        (StatusCode::FORBIDDEN, "unknown_tenant")
    );
    let (status, _) = l.get("/v1/admin/tenant", &admin).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let start = std::time::Instant::now();
    loop {
        let q = common::ask(
            USER,
            "invoice:read",
            &common::Seed {
                key: l.a.key.clone(),
                tid: l.a.tid.clone(),
                org: l.a.org.clone(),
                project: l.a.project.clone(),
                assignment: "ra_0193a1b2-c3d4-7a00-8000-0000000000a2".parse().unwrap(),
            },
        );
        let (status, _) = l.post("/access/v1/evaluation", &service, &q).await;
        if status == StatusCode::FORBIDDEN {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_millis(2500),
            "a deleted tenant still answers"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Its event stream ends; no job visits it any more.
    assert!(
        ends_within(&mut stream, Duration::from_secs(8)).await,
        "its stream still runs"
    );
    let tx = l.d.owner.transaction().await.unwrap();
    let listed = tutela_store::tenants(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert!(!listed.contains(&l.a.key));
    assert!(listed.contains(&l.b.key));
    // B is untouched.
    assert!(l.reads(&l.b, USER, &l.b.project, &l.b.org, 0).await);

    // Its chain is kept and whole; the deletion is its last record, and the
    // deployment's chain has it too.
    let chain = common::audit_of(&mut l.d.owner, &l.a.key).await;
    let last = chain.last().unwrap();
    assert_eq!(
        (last["action"].as_str(), last["actor"]["id"].as_str()),
        (Some("tutela_tenant:delete"), Some(ADMIN))
    );
    let dep = deployment_records(&mut l.d.owner, "tutela_tenant:delete").await;
    assert_eq!(dep[0]["details"]["tid"], l.a.tid);
    assert_eq!(dep[0]["actor"]["id"], ADMIN);

    // The operator restores it; then its owner deletes it again over gRPC.
    tutelad::lifecycle::restore_tenant(&mut l.d.owner, &ISS.parse().unwrap(), &l.a.key)
        .await
        .unwrap();
    assert_eq!(l.get("/v1/whoami", &service).await.0, StatusCode::OK);
    let mut g = l.grpc().await;
    let t = g
        .delete_tenant(with_token(
            &l.console(ADMIN_SA, &l.a),
            pb::DeleteTenantRequest {},
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(!t.purge_after.is_empty());
    let e = g
        .get_tenant(with_token(&admin, pb::GetTenantRequest {}))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);

    // The purge after the grace: every row of its data goes; its audit
    // chain, its revision and its directory row stay.
    let before = chain.len();
    let early = tutelad::expiry::purge(&l.st.db, &l.st.metrics, &ISS.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(early.tenants, 0, "purged before its grace");
    age(&l.d, "tenant", "tenant_id", &l.a.tid).await;
    let p = tutelad::expiry::purge(&l.st.db, &l.st.metrics, &ISS.parse().unwrap())
        .await
        .unwrap();
    assert_eq!((p.tenants, p.failed), (1, 0));
    let again = tutelad::expiry::purge(&l.st.db, &l.st.metrics, &ISS.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(again.tenants, 0);
    let su = l.d.superuser().await;
    let tables: Vec<String> = su
        .query(
            "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' \
             WHERE n.nspname = 'tutela' AND c.relkind = 'r'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    let kept = [
        "tenant",
        "tenant_rev",
        "audit_record",
        "audit_head",
        "audit_forward",
    ];
    for t in &tables {
        let n: i64 = su
            .query_one(
                &format!("SELECT count(*) FROM tutela.\"{t}\" WHERE tenant_id = $1"),
                &[&l.a.tid],
            )
            .await
            .unwrap()
            .get(0);
        if kept.contains(&t.as_str()) {
            continue;
        }
        assert_eq!(n, 0, "{t} still holds the purged tenant's rows");
        let b: i64 = su
            .query_one(
                &format!("SELECT count(*) FROM tutela.\"{t}\" WHERE tenant_id = $1"),
                &[&l.b.tid],
            )
            .await
            .unwrap()
            .get(0);
        if ["org", "role_assignment", "scope_path"].contains(&t.as_str()) {
            assert!(b > 0, "{t} lost the other tenant's rows");
        }
    }
    let chain = common::audit_of(&mut l.d.owner, &l.a.key).await;
    assert!(chain.len() > before);
    assert_eq!(chain.last().unwrap()["action"], "tutela_tenant:purge");
    assert_eq!(
        deployment_records(&mut l.d.owner, "tutela_tenant:purge")
            .await
            .len(),
        1
    );
    let purged: Option<std::time::SystemTime> = su
        .query_one(
            "SELECT purged_at FROM tutela.tenant WHERE tenant_id = $1",
            &[&l.a.tid],
        )
        .await
        .unwrap()
        .get(0);
    assert!(purged.is_some());
    // A purged tenant cannot be restored.
    assert!(
        tutelad::lifecycle::restore_tenant(&mut l.d.owner, &ISS.parse().unwrap(), &l.a.key)
            .await
            .is_err()
    );
    let _ = STEP_UP;
    l.finish().await;
}

/// `tutelad tenant create` and `tutelad tenant restore`, the real binary.
#[tokio::test]
async fn the_tenant_command_makes_a_tenant_as_the_owner() {
    let Some(mut d) = common::migrated().await else {
        return;
    };
    common::publish(&mut d.owner, MANIFEST, None).await;
    let run = |args: Vec<&str>, vars: Vec<(&'static str, String)>| {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_tutelad"));
        cmd.args(args).env_clear().envs(vars);
        async move { cmd.output().await.unwrap() }
    };
    let vars = vec![
        ("TUTELA_OWNER_DATABASE_URL", d.owner_url.clone()),
        ("TUTELA_ISSUER", common::OWN_ISS.to_owned()),
    ];
    let out = run(vec!["tenant", "create", "--name", "Acme"], vars.clone()).await;
    assert_eq!(
        out.status.code(),
        Some(1),
        "a tenant with no owner was made"
    );
    let out = run(
        vec![
            "tenant",
            "create",
            "--name",
            "Acme",
            "--admin",
            ADMIN_SA,
            "--admin-upstream",
            "https://kc.example.test/realms/acme=bob",
        ],
        vars.clone(),
    )
    .await;
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let made: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(made["iss"], common::OWN_ISS);
    assert_eq!(made["owners"].as_array().unwrap().len(), 2);
    let key = TenantKey::new(
        common::OWN_ISS.parse().unwrap(),
        made["tid"].as_str().unwrap().parse().unwrap(),
    );
    let tx = d.owner.transaction().await.unwrap();
    assert_eq!(
        tutela_store::tenant_info(&tx, &key)
            .await
            .unwrap()
            .name
            .as_deref(),
        Some("Acme")
    );
    tx.commit().await.unwrap();
    // Restoring a tenant that is not deleted fails; the missing setting is named.
    let out = run(
        vec!["tenant", "restore", made["tid"].as_str().unwrap()],
        vars.clone(),
    )
    .await;
    assert_eq!(out.status.code(), Some(1));
    let out = run(vec!["tenant", "create", "--admin", ADMIN_SA], vec![]).await;
    assert!(String::from_utf8_lossy(&out.stderr).contains("TUTELA_OWNER_DATABASE_URL is not set"));
    d.finish().await;
}
