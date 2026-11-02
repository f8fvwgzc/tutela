//! The Service gate's tenant checks (ROADMAP.md, THREAT-MODEL.md TM-14), on
//! a real Postgres, with the service's own role and pool:
//!
//! - a query with no tenant set returns zero rows;
//! - a cross-tenant read fails at row-level security even with an injected
//!   code bug. The bug is a query with the tenant filter left out, so these
//!   tests go around the application's filter, not through it. Each one also
//!   shows that the row exists and that the same query leaks when row-level
//!   security is off, so nothing here passes by accident.
#![cfg(test)]

mod common;

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use common::{
    ISS, Issuer, SERVICE, TestDb, USER, config, connect, http, migrated, now, state, trust,
};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{OrgId, TenantKey};
use tutela_pdp::model::{AppName, Class, GroupKey, RoleKey};
use tutela_pdp::{Member, PathEntry, Subject};
use tutela_sdk::Identity;
use tutela_sdk::http::{AuthLayer, Protocol};
use tutela_store::tokio_postgres::Client;
use tutela_store::{Publish, StoreErrorKind};
use tutelad::db::Db;
use tutelad::tenant::Tenant;

const AUD: &str = "tutela-authz";
const MANIFEST: &str = "version = 1\n[app]\nname = \"rls_test\"\n";

/// Every table with tenant data today. The test also reads the catalog, so a
/// new tenant table that nobody seeds below fails here, on purpose.
const TENANT_TABLES: [&str; 14] = [
    "boundary_rule",
    "exchanged_token",
    "field_rule",
    "group",
    "group_member",
    "model_proposal",
    "model_revision",
    "org",
    "principal",
    "role_assignment",
    "scope_path",
    "tenant_rev",
    "tenant_setting",
    "upstream_account",
];

struct World {
    db: TestDb,
    a: TenantKey,
    b: TenantKey,
    a_org: OrgId,
}

fn entry(t: &str, id: &str) -> PathEntry {
    PathEntry::new(t.parse().unwrap(), id.parse().unwrap())
}

/// One tenant with a row in every tenant table but `model_revision`.
async fn fill(owner: &mut Client) -> (TenantKey, OrgId) {
    let t = common::tenant(owner).await;
    let tx = owner.transaction().await.unwrap();
    let (org, _) = tutela_store::add_org(&tx, &t).await.unwrap();
    let org_entry = entry("org", &org.to_string());
    let user: Principal = USER.parse().unwrap();
    let staff = GroupKey::parse("staff").unwrap();
    tutela_store::create_group(&tx, &t, &org, &staff, "Staff")
        .await
        .unwrap();
    tutela_store::add_member(&tx, &t, &staff, &Member::Principal(user.clone()), None)
        .await
        .unwrap();
    tutela_store::assign(
        &tx,
        &t,
        &Subject::Principal(user),
        &RoleKey::parse("viewer").unwrap(),
        &org_entry,
        None,
    )
    .await
    .unwrap();
    let project = entry("project", "p1");
    tutela_store::put_scope(&tx, &t, &project, std::slice::from_ref(&org_entry), true)
        .await
        .unwrap();
    tutela_store::put_field_rule(
        &tx,
        &t,
        &project,
        &"contract.title".parse().unwrap(),
        None,
        Level::Read,
        None,
    )
    .await
    .unwrap();
    tutela_store::set_two_person(&tx, &t, true, USER)
        .await
        .unwrap();
    tutela_store::propose(
        &tx,
        &t,
        &tutela_store::NewProposal {
            app: &tutela_pdp::model::AppName::parse("crm").unwrap(),
            source: "version = 1",
            base_version: 0,
            base_digest: "none",
            restores: None,
            class: tutela_pdp::model::Class::Neutral,
            diff: "",
            impact: "{}",
            impact_digest: "none",
            impact_complete: true,
            rev: 0,
            proposed_by: USER,
        },
    )
    .await
    .unwrap();
    let kc: tutela_contracts::tenant::Issuer =
        "https://kc.example.test/realms/acme".parse().unwrap();
    tutela_store::provision_user(&tx, &t, &kc, "someone")
        .await
        .unwrap();
    tutela_store::note_exchange(
        &tx,
        &t,
        &kc,
        "a-jti",
        std::time::SystemTime::now() + std::time::Duration::from_secs(300),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (t, org)
}

/// Two tenants, each with rows in every tenant table.
async fn world() -> Option<World> {
    let mut db = migrated().await?;
    let (a, a_org) = fill(&mut db.owner).await;
    let (b, _) = fill(&mut db.owner).await;
    let tx = db.owner.transaction().await.unwrap();
    tutela_store::publish_manifest(
        &tx,
        &Publish {
            app: &AppName::parse("rls_test").unwrap(),
            source: MANIFEST,
            expected: None,
            class: Class::Neutral,
            diff: "first",
            author: None,
            approvers: &[],
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Some(World { db, a, b, a_org })
}

/// The tables the catalog says hold tenant data.
async fn tenant_tables(c: &Client) -> Vec<String> {
    let mut t: Vec<String> = c
        .query(
            "SELECT c.relname::text FROM pg_class c \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' \
             WHERE n.nspname = 'tutela' AND c.relkind = 'r' AND c.relname <> 'tenant'",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    t.sort();
    t
}

async fn count(c: &Client, sql: &str) -> i64 {
    c.query_one(sql, &[]).await.unwrap().get(0)
}

fn verified_tenant(t: &TenantKey) -> Tenant {
    let id = Identity::External(tutela_sdk::ExternalToken {
        tenant: t.clone(),
        sub: "test".to_owned(),
        azp: None,
        exp: now() + 60,
    });
    Tenant::of(&id)
}

/// A query with no tenant set returns zero rows, on every tenant table,
/// in and out of a transaction, even when it names a tenant.
#[tokio::test]
async fn with_no_tenant_set_every_table_returns_zero_rows() {
    let Some(w) = world().await else { return };
    let root = w.db.superuser().await;
    let tables = tenant_tables(&root).await;
    assert_eq!(tables, TENANT_TABLES, "seed a new tenant table in fill()");
    let mut service = connect(&w.db.service_url).await;
    let (a, b) = (w.a.tid.to_string(), w.b.tid.to_string());
    for t in &tables {
        // The rows are there, for both tenants.
        for tid in [&a, &b] {
            let rows = count(
                &root,
                &format!("SELECT count(*) FROM tutela.\"{t}\" WHERE tenant_id = '{tid}'"),
            )
            .await;
            assert!(rows > 0, "{t} has no row for {tid}: seed it in fill()");
        }
        let all = format!("SELECT count(*) FROM tutela.\"{t}\"");
        let named = format!("{all} WHERE tenant_id = '{a}'");
        assert_eq!(count(&service, &all).await, 0, "{t}");
        assert_eq!(count(&service, &named).await, 0, "{t}");
        let tx = service.transaction().await.unwrap();
        assert_eq!(tx.query_one(&all, &[]).await.unwrap().get::<_, i64>(0), 0);
        drop(tx);
    }
    w.db.finish().await;
}

#[derive(Deserialize)]
struct Leak {
    other: Option<String>,
}

/// **The injected bug.** A handler that takes the verified tenant, as every
/// handler does, but whose query has no tenant filter, or names another
/// tenant from the request.
async fn leaky_handler(
    State(db): State<Db>,
    tenant: Tenant,
    Query(leak): Query<Leak>,
) -> Json<Vec<String>> {
    let mut conn = db.conn().await.unwrap();
    let tx = conn.begin(&tenant).await.unwrap();
    let rows = match &leak.other {
        None => {
            tx.query("SELECT tenant_id FROM tutela.role_assignment", &[])
                .await
        }
        Some(other) => {
            tx.query(
                "SELECT tenant_id FROM tutela.role_assignment WHERE tenant_id = $1",
                &[other],
            )
            .await
        }
    }
    .unwrap();
    Json(rows.iter().map(|r| r.get(0)).collect())
}

/// The bug behind the real token check and the real pool, over HTTP. RLS
/// stops it, and with RLS off the same request leaks: so RLS is what stops
/// it, not any code.
#[tokio::test]
async fn a_cross_tenant_read_fails_at_rls_with_an_injected_bug() {
    let Some(w) = world().await else { return };
    let (a, b) = (w.a.tid.to_string(), w.b.tid.to_string());
    let issuer = Issuer::new();
    let cfg = config(&w.db.service_url, trust(&[a.clone(), b.clone()]));
    let st = state(&cfg, &issuer);
    let app = Router::new()
        .route("/leak", get(leaky_handler))
        .with_state(st.db.clone())
        .layer(AuthLayer::new(Arc::clone(&st.verifier), Protocol::Http));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/leak", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await });

    let token = issuer.sign(ISS, &a, AUD, now());
    let c = http();
    let read = |query: String| {
        let req = c.get(format!("{url}{query}")).bearer_auth(&token);
        async move {
            let r = req.send().await.unwrap();
            assert_eq!(r.status(), StatusCode::OK);
            r.json::<Vec<String>>().await.unwrap()
        }
    };
    let naming_b = format!("?other={b}");

    // No filter: A's rows only. A filter that names B: nothing.
    assert_eq!(read(String::new()).await, std::slice::from_ref(&a));
    assert_eq!(read(naming_b.clone()).await, Vec::<String>::new());

    // B's row is there, and the bug's own query finds it from outside RLS.
    let root = w.db.superuser().await;
    assert_eq!(
        count(&root, "SELECT count(*) FROM tutela.role_assignment").await,
        2
    );

    // With row-level security off, the same request with the same token
    // leaks. Nothing but RLS stood in the way.
    root.batch_execute("ALTER TABLE tutela.role_assignment DISABLE ROW LEVEL SECURITY")
        .await
        .unwrap();
    let mut leaked = read(String::new()).await;
    leaked.sort();
    let mut both = vec![a.clone(), b.clone()];
    both.sort();
    assert_eq!(leaked, both, "the bug must leak without RLS");
    assert_eq!(read(naming_b).await, std::slice::from_ref(&b));
    w.db.finish().await;
}

/// The same bug on every tenant table.
#[tokio::test]
async fn every_table_hides_the_other_tenant_from_a_query_with_no_filter() {
    let Some(w) = world().await else { return };
    let cfg = config(&w.db.service_url, trust(&[w.a.tid.to_string()]));
    let db = Db::connect(&cfg.database_url, 2).unwrap();
    let tenant = verified_tenant(&w.a);
    let (a, b) = (w.a.tid.to_string(), w.b.tid.to_string());
    let mut conn = db.conn().await.unwrap();
    let tx = conn.begin(&tenant).await.unwrap();
    for t in TENANT_TABLES {
        let rows = tx
            .query(&format!("SELECT tenant_id FROM tutela.\"{t}\""), &[])
            .await
            .unwrap();
        assert!(!rows.is_empty(), "{t}: tenant A has rows");
        assert!(rows.iter().all(|r| r.get::<_, &str>(0) == a), "{t}");
        let theirs = tx
            .query(
                &format!("SELECT tenant_id FROM tutela.\"{t}\" WHERE tenant_id = $1"),
                &[&b],
            )
            .await
            .unwrap();
        assert!(theirs.is_empty(), "{t}");
    }
    drop(tx);
    w.db.finish().await;
}

/// Writes are held the same way: a row for another tenant cannot be made,
/// changed, moved or deleted.
#[tokio::test]
async fn a_cross_tenant_write_fails_at_rls_with_an_injected_bug() {
    let Some(w) = world().await else { return };
    let db = Db::connect(&w.db.service_url, 2).unwrap();
    let tenant = verified_tenant(&w.a);
    let b = w.b.tid.to_string();
    let root = w.db.superuser().await;
    let before = count(
        &root,
        "SELECT count(*) FROM tutela.role_assignment WHERE role_id = 'viewer'",
    )
    .await;

    let mut conn = db.conn().await.unwrap();

    // A new row under B's id: refused by WITH CHECK.
    let tx = conn.begin(&tenant).await.unwrap();
    let e = tx
        .execute(
            "INSERT INTO tutela.org (tenant_id, org_id) \
             VALUES ($1, 'org_0193a1b2-c3d4-7e5f-8a6b-000000000001')",
            &[&b],
        )
        .await
        .unwrap_err();
    assert_eq!(e.code().map(|c| c.code()), Some("42501"), "{e:?}");
    drop(tx);

    // Giving A's row to B: refused too.
    let tx = conn.begin(&tenant).await.unwrap();
    let e = tx
        .execute("UPDATE tutela.group SET tenant_id = $1", &[&b])
        .await
        .unwrap_err();
    assert!(e.code().is_some(), "{e:?}");
    drop(tx);

    // Changing or deleting B's rows reaches nothing.
    let tx = conn.begin(&tenant).await.unwrap();
    let n = tx
        .execute(
            "UPDATE tutela.role_assignment SET role_id = 'owner' WHERE tenant_id = $1",
            &[&b],
        )
        .await
        .unwrap();
    assert_eq!(n, 0);
    let n = tx
        .execute(
            "DELETE FROM tutela.role_assignment WHERE tenant_id = $1",
            &[&b],
        )
        .await
        .unwrap();
    assert_eq!(n, 0);
    // With no filter, only A's own row is touched.
    let n = tx
        .execute("UPDATE tutela.role_assignment SET role_id = 'owner'", &[])
        .await
        .unwrap();
    assert_eq!(n, 1);
    drop(tx);

    assert_eq!(
        count(
            &root,
            "SELECT count(*) FROM tutela.role_assignment WHERE role_id = 'viewer'"
        )
        .await,
        before
    );
    w.db.finish().await;
}

/// A bug that passes the wrong key to a store call inside a tenant's
/// transaction fails: a transaction belongs to one tenant.
#[tokio::test]
async fn a_store_call_with_another_tenants_key_fails() {
    let Some(w) = world().await else { return };
    let db = Db::connect(&w.db.service_url, 2).unwrap();
    let mut conn = db.conn().await.unwrap();
    let tx = conn.begin(&verified_tenant(&w.a)).await.unwrap();
    assert_eq!(tx.tenant(), &w.a);
    let e = tutela_store::load(&tx, &w.b).await.unwrap_err();
    assert_eq!(e.kind(), StoreErrorKind::TenantMismatch);
    let e = tutela_store::rev(&tx, &w.b).await.unwrap_err();
    assert_eq!(e.kind(), StoreErrorKind::TenantMismatch);
    // Its own tenant still works.
    let bundle = tutela_store::load(&tx, &w.a).await.unwrap();
    assert_eq!(bundle.data.bindings.len(), 1);
    // The right id with another issuer is no tenant at all.
    let wrong = TenantKey::new("https://other.example.test".parse().unwrap(), w.a.tid);
    let e = tutela_store::rev(&tx, &wrong).await.unwrap_err();
    assert_eq!(e.kind(), StoreErrorKind::UnknownTenant);
    drop(tx);
    w.db.finish().await;
}

/// TM-14's pooled-connection test. The setting ends with the transaction on
/// commit and on rollback, and the next transaction on the same connection
/// sees nothing until it enters its own tenant.
#[tokio::test]
async fn a_session_keeps_no_tenant_after_its_transaction() {
    let Some(w) = world().await else { return };
    let mut service = connect(&w.db.service_url).await;
    for commit in [true, false] {
        let tx = service.transaction().await.unwrap();
        tutela_store::enter(&tx, &w.a).await.unwrap();
        let rows = tx
            .query_one("SELECT count(*) FROM tutela.org", &[])
            .await
            .unwrap();
        assert_eq!(rows.get::<_, i64>(0), 1);
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        assert_eq!(count(&service, "SELECT count(*) FROM tutela.org").await, 0);
    }
    w.db.finish().await;
}

async fn backend(tx: &tutelad::db::TenantTx<'_>) -> i32 {
    tx.query_one("SELECT pg_backend_pid()", &[])
        .await
        .unwrap()
        .get(0)
}

/// The real pool, with one connection, so a reuse is certain. Even a bug
/// that sets the tenant for the session does not reach the next checkout.
#[tokio::test]
async fn the_pool_gives_out_no_tenant_even_after_a_session_level_bug() {
    let Some(w) = world().await else { return };
    let db = Db::connect(&w.db.service_url, 1).unwrap();
    let tenant = verified_tenant(&w.a);
    let mut conn = db.conn().await.unwrap();
    let tx = conn.begin(&tenant).await.unwrap();
    let pid = backend(&tx).await;
    tx.commit().await.unwrap();
    drop(conn);
    assert_eq!(db.leftover_tenant().await.unwrap(), None);

    // Rolled back by a drop.
    let mut conn = db.conn().await.unwrap();
    drop(conn.begin(&tenant).await.unwrap());
    drop(conn);
    assert_eq!(db.leftover_tenant().await.unwrap(), None);

    // The bug: `false` makes the setting last for the session.
    let mut conn = db.conn().await.unwrap();
    let tx = conn.begin(&tenant).await.unwrap();
    assert_eq!(backend(&tx).await, pid, "the pool reuses one connection");
    tx.query_one(
        "SELECT set_config('tutela.tenant_id', $1, false)",
        &[&w.b.tid.to_string()],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    drop(conn);
    assert_eq!(db.leftover_tenant().await.unwrap(), None);
    db.check_ready().await.unwrap();
    w.db.finish().await;
}

#[derive(Deserialize)]
struct Who {
    tid: String,
    rev: u64,
}

/// Over HTTP: the tenant comes from the token, and a header, a query or a
/// body that names another tenant changes nothing.
#[tokio::test]
async fn the_tenant_comes_only_from_the_token() {
    let Some(w) = world().await else { return };
    let (a, b) = (w.a.tid.to_string(), w.b.tid.to_string());
    // Give B another revision, so an answer shows whose row it read.
    {
        let mut owner = connect(&w.db.owner_url).await;
        let tx = owner.transaction().await.unwrap();
        tutela_store::add_org(&tx, &w.b).await.unwrap();
        tx.commit().await.unwrap();
    }
    let issuer = Issuer::new();
    let cfg = config(&w.db.service_url, trust(&[a.clone(), b.clone()]));
    let s = common::start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let ask = |token: String| {
        let req = c
            .get(s.api_url(&format!("/v1/whoami?tid={b}&tenant={b}")))
            .bearer_auth(token)
            .header("x-tenant-id", &b)
            .header("tutela-tenant", &b)
            .body(format!("{{\"tid\": \"{b}\"}}"));
        async move { req.send().await.unwrap().json::<Who>().await.unwrap() }
    };
    let from_a = ask(issuer.sign(ISS, &a, AUD, now())).await;
    let from_b = ask(issuer.sign(ISS, &b, AUD, now())).await;
    assert_eq!(from_a.tid, a);
    assert_eq!(from_b.tid, b);
    assert_eq!(from_b.rev, from_a.rev + 1);
    s.stop().await.unwrap();
    w.db.finish().await;
}

/// The grants a tenant-aware service needs are enough, and they are all it
/// has.
#[tokio::test]
async fn the_service_role_has_what_it_needs_and_nothing_else() {
    let Some(w) = world().await else { return };
    let db = Db::connect(&w.db.service_url, 2).unwrap();
    let tenant = verified_tenant(&w.a);
    let mut conn = db.conn().await.unwrap();

    // It works through the store, inside its tenant.
    let tx = conn.begin(&tenant).await.unwrap();
    let rev = tutela_store::rev(&tx, &w.a).await.unwrap();
    let (rule, new) = tutela_store::assign(
        &tx,
        &w.a,
        &Subject::Group(GroupKey::parse("staff").unwrap()),
        &RoleKey::parse("viewer").unwrap(),
        &entry("org", &w.a_org.to_string()),
        None,
    )
    .await
    .unwrap();
    assert_eq!(new, rev + 1);
    tutela_store::unassign(&tx, &w.a, &rule).await.unwrap();
    tx.commit().await.unwrap();

    let service = connect(&w.db.service_url).await;
    for sql in [
        // It reads the approver keys to check a token (ADR-0026), and holds
        // only public keys there. It never writes them.
        "DELETE FROM tutela.approver_key",
        "INSERT INTO tutela.tenant (tenant_id, iss) VALUES \
         ('ten_0193a1b2-c3d4-7e5f-8a6b-000000000009', 'https://x.example.test')",
        "DELETE FROM tutela.tenant",
        "UPDATE tutela.app_manifest SET version = 9",
        "DELETE FROM tutela.schema_migration",
        "CREATE TABLE tutela.mine (id int)",
        "DROP TABLE tutela.role_assignment",
        "ALTER TABLE tutela.role_assignment DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE tutela.role_assignment NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON tutela.role_assignment",
        "CREATE POLICY open ON tutela.role_assignment USING (true)",
    ] {
        let e = service.batch_execute(sql).await.unwrap_err();
        assert!(e.code().is_some(), "{sql}: {e:?}");
    }
    let rows = service
        .query("SELECT tenant_id FROM tutela.tenant", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    w.db.finish().await;
}

#[tokio::test]
async fn grants_are_refused_for_the_owner_and_for_a_name_that_is_not_plain() {
    let Some(mut d) = migrated().await else {
        return;
    };
    for role in [common::OWNER, "bad-role", "x; DROP TABLE y", ""] {
        let e = tutela_store::grant_service(&mut d.owner, role)
            .await
            .unwrap_err();
        assert_eq!(e.kind(), StoreErrorKind::Invalid, "{role}");
    }
    d.finish().await;
}

async fn isolation_detail(c: &Client) -> Option<&'static str> {
    tutela_store::check_isolation(c)
        .await
        .err()
        .and_then(|e| e.detail())
}

/// TM-14: "A CI check fails if the app role owns a table or has BYPASSRLS",
/// and `tutelad` makes the same check at run time.
#[tokio::test]
async fn an_unsafe_role_or_schema_is_refused() {
    let Some(w) = world().await else { return };
    let root = w.db.superuser().await;
    let service = connect(&w.db.service_url).await;
    assert_eq!(isolation_detail(&service).await, None);

    // Roles.
    assert_eq!(
        isolation_detail(&root).await,
        Some("the role is a superuser")
    );
    assert_eq!(
        isolation_detail(&w.db.owner).await,
        Some("the role owns a table in the schema")
    );
    let unique = format!("{:x}", now());
    let bypass = format!("tutela_test_bypass_{unique}");
    let member = format!("tutela_test_member_{unique}");
    root.batch_execute(&format!(
        "CREATE ROLE {bypass} LOGIN BYPASSRLS PASSWORD 'x'; \
         CREATE ROLE {member} LOGIN PASSWORD 'x' IN ROLE {owner};",
        owner = common::OWNER
    ))
    .await
    .unwrap();
    let as_role = |role: &str| common::with(&w.db.base, &w.db.name, role, "x");
    let c = connect(&as_role(&bypass)).await;
    assert_eq!(isolation_detail(&c).await, Some("the role has BYPASSRLS"));
    let c = connect(&as_role(&member)).await;
    assert_eq!(
        isolation_detail(&c).await,
        Some("the role owns a table in the schema")
    );

    // Schema.
    let step = |grant: &'static str, revoke: &'static str, why: &'static str| {
        let (root, service) = (&root, &service);
        async move {
            root.batch_execute(grant).await.unwrap();
            assert_eq!(isolation_detail(service).await, Some(why), "{grant}");
            root.batch_execute(revoke).await.unwrap();
            assert_eq!(isolation_detail(service).await, None, "{revoke}");
        }
    };
    let schema_grant = format!("GRANT CREATE ON SCHEMA tutela TO {SERVICE}");
    let schema_revoke = format!("REVOKE CREATE ON SCHEMA tutela FROM {SERVICE}");
    root.batch_execute(&schema_grant).await.unwrap();
    assert_eq!(
        isolation_detail(&service).await,
        Some("the role may create objects in the schema")
    );
    root.batch_execute(&schema_revoke).await.unwrap();
    let no_rls = "a tenant table has no forced row-level security";
    step(
        "ALTER TABLE tutela.org NO FORCE ROW LEVEL SECURITY",
        "ALTER TABLE tutela.org FORCE ROW LEVEL SECURITY",
        no_rls,
    )
    .await;
    step(
        "ALTER TABLE tutela.org DISABLE ROW LEVEL SECURITY",
        "ALTER TABLE tutela.org ENABLE ROW LEVEL SECURITY",
        no_rls,
    )
    .await;
    step(
        "DROP POLICY tenant_isolation ON tutela.org",
        "CREATE POLICY tenant_isolation ON tutela.org \
         USING (tenant_id = current_setting('tutela.tenant_id', true)) \
         WITH CHECK (tenant_id = current_setting('tutela.tenant_id', true))",
        no_rls,
    )
    .await;
    step(
        "CREATE TABLE tutela.new_table (tenant_id text)",
        "DROP TABLE tutela.new_table",
        no_rls,
    )
    .await;
    step(
        "CREATE FUNCTION tutela.peek() RETURNS bigint LANGUAGE sql SECURITY DEFINER \
         AS 'SELECT count(*) FROM tutela.org'",
        "DROP FUNCTION tutela.peek",
        "the schema has a SECURITY DEFINER function",
    )
    .await;
    step(
        "CREATE VIEW tutela.peek AS SELECT * FROM tutela.org",
        "DROP VIEW tutela.peek",
        "the schema has an owner-rights view",
    )
    .await;

    root.batch_execute(&format!("DROP ROLE {bypass}; DROP ROLE {member};"))
        .await
        .unwrap();
    w.db.finish().await;
}

/// `tutelad` will not start on a role that can see every tenant. A service
/// that got past that check still runs no query.
#[tokio::test]
async fn tutelad_refuses_to_serve_on_an_unsafe_role() {
    let Some(mut w) = world().await else { return };
    let cfg = config(&w.db.owner_url, trust(&[w.a.tid.to_string()]));
    let e = tutelad::run(cfg.clone(), std::future::ready(()))
        .await
        .unwrap_err();
    let text = format!("{e:#}");
    assert!(text.contains("refusing to serve"), "{text}");
    assert!(text.contains("owns a table"), "{text}");

    let issuer = Issuer::new();
    let s = common::start(&cfg, state(&cfg, &issuer)).await;
    let c = http();
    let r = c
        .get(s.api_url("/v1/whoami"))
        .bearer_auth(issuer.sign(ISS, &w.a.tid.to_string(), AUD, now()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["type"], "urn:tutela:problem:unavailable");
    let r = c.get(s.ops_url("/readyz")).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    s.stop().await.unwrap();

    // A manifest publish on the owner's connection left no tenant entered.
    let tx = w.db.owner.transaction().await.unwrap();
    tutela_store::rev(&tx, &w.a).await.unwrap();
    drop(tx);
    w.db.finish().await;
}
