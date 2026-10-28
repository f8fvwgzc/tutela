//! `tutela-store` against a real Postgres.
//!
//! `TUTELA_TEST_DATABASE_URL` names a server and a role that may create
//! roles and databases (for example
//! `host=127.0.0.1 port=5432 user=postgres password=postgres dbname=postgres`).
//! Each test makes its own database, owned by a role that is **not** a
//! superuser, so `FORCE ROW LEVEL SECURITY` applies to everything the test
//! does. With the variable unset, each test says so and passes, except when
//! `TUTELA_REQUIRE_DATABASE=1` (CI sets it): then a missing database fails.

use std::sync::Arc;

use crate::{StoreError, TenantBundle};
use tokio_postgres::{Client, NoTls};
use tutela_contracts::decision::Effect;
use tutela_contracts::keys::ActionKey;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, OrgId, TenantKey};
use tutela_pdp::model::{AppName, Class, GroupKey, Model, RoleKey};
use tutela_pdp::{
    CheckRequest, FilterExpr, ListFilter, ListFilterRequest, LoadError, Member, PathEntry, Pdp,
    ResourceRef, Subject,
};

const OWNER: &str = "tutela_test_owner";
const OWNER_PASSWORD: &str = "tutela_test_owner";

const MANIFEST: &str = r#"
version = 1
[app]
name = "store_test"

[types.department]
parent = "org"
container = true

[types.matter]
parent = "department"
container = true

[types.contract]
parent = "matter"
[types.contract.fields]
title = { sensitivity = "internal" }

[roles.reader]
grants = { department = "read", matter = "read", contract = "read" }
"#;

/// A test database. Dropped by [`Db::finish`] when the test passes.
struct Db {
    admin: Client,
    name: String,
    client: Client,
}

fn base_url() -> Option<String> {
    match std::env::var("TUTELA_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => Some(u),
        _ => {
            assert!(
                std::env::var("TUTELA_REQUIRE_DATABASE").as_deref() != Ok("1"),
                "TUTELA_REQUIRE_DATABASE=1 but TUTELA_TEST_DATABASE_URL is not set"
            );
            eprintln!("skipped: set TUTELA_TEST_DATABASE_URL to run the tutela-store tests");
            None
        }
    }
}

async fn connect(url: &str) -> Client {
    let (client, conn) = tokio_postgres::connect(url, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

/// A key=value connection string with `dbname`, `user` and `password`
/// replaced.
fn with(url: &str, db: &str, user: &str, password: &str) -> String {
    let mut parts: Vec<String> = url
        .split_whitespace()
        .filter(|p| {
            !p.starts_with("dbname=") && !p.starts_with("user=") && !p.starts_with("password=")
        })
        .map(str::to_owned)
        .collect();
    parts.push(format!("dbname={db}"));
    parts.push(format!("user={user}"));
    parts.push(format!("password={password}"));
    parts.join(" ")
}

async fn db() -> Option<Db> {
    let base = base_url()?;
    let admin = connect(&base).await;
    let exists = admin
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&OWNER])
        .await
        .unwrap()
        .is_some();
    if !exists {
        // Two tests may race to make the role; one of them wins.
        let _ = admin
            .batch_execute(&format!(
                "CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '{OWNER_PASSWORD}'"
            ))
            .await;
    }
    let name = format!("tutela_test_{}", uuid::Uuid::now_v7().simple());
    admin
        .batch_execute(&format!("CREATE DATABASE {name} OWNER {OWNER}"))
        .await
        .unwrap();
    let url = with(&base, &name, OWNER, OWNER_PASSWORD);
    let mut client = connect(&url).await;
    let applied = crate::migrate(&mut client).await.unwrap();
    assert_eq!(applied, [1]);
    Some(Db {
        admin,
        name,
        client,
    })
}

impl Db {
    async fn finish(self) {
        drop(self.client);
        self.admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn iss() -> Issuer {
    "https://idp.example.test/realms/kestrel".parse().unwrap()
}

fn user(n: u32) -> Principal {
    format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}")
        .parse()
        .unwrap()
}

fn entry(t: &str, id: &str) -> PathEntry {
    PathEntry::new(t.parse().unwrap(), id.parse().unwrap())
}

fn org(o: &OrgId) -> PathEntry {
    entry("org", &o.to_string())
}

fn role(s: &str) -> RoleKey {
    RoleKey::parse(s).unwrap()
}

fn gkey(s: &str) -> GroupKey {
    GroupKey::parse(s).unwrap()
}

/// A tenant with one org.
async fn tenant(c: &mut Client) -> (TenantKey, OrgId) {
    let tx = c.transaction().await.unwrap();
    let t = crate::create_tenant(&tx, &iss()).await.unwrap();
    let (o, rev) = crate::add_org(&tx, &t).await.unwrap();
    assert_eq!(rev, 1);
    tx.commit().await.unwrap();
    (t, o)
}

async fn load(c: &mut Client, t: &TenantKey) -> TenantBundle {
    let tx = c.transaction().await.unwrap();
    let b = crate::load(&tx, t).await.unwrap();
    tx.commit().await.unwrap();
    b
}

fn pdp_of(t: &TenantKey, b: &TenantBundle) -> Pdp {
    let model = Arc::new(Model::from_toml(MANIFEST).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(t.clone(), b.rev, model, b.data.clone()).unwrap();
    pdp
}

fn read(t: &TenantKey, p: &Principal, ty: &str, id: &str, path: Vec<PathEntry>) -> CheckRequest {
    CheckRequest {
        tenant: t.clone(),
        subject: p.clone(),
        actors: vec![],
        action: ActionKey::parse(&format!("{ty}:read")).unwrap(),
        resource: ResourceRef {
            type_name: ty.parse().unwrap(),
            id: id.parse().unwrap(),
            path,
            attrs: Default::default(),
        },
        fields: None,
        at_least_revision: None,
    }
}

/// Whether a row with these ancestors matches a list filter: the subset of
/// the condition AST that a filter without field conditions uses.
fn row_matches(f: &ListFilter, id: &str, ancestors: &[PathEntry]) -> bool {
    fn holds(e: &FilterExpr, id: &str, ancestors: &[PathEntry]) -> bool {
        match e {
            FilterExpr::True => true,
            FilterExpr::False => false,
            FilterExpr::And { args } => args.iter().all(|a| holds(a, id, ancestors)),
            FilterExpr::Or { args } => args.iter().any(|a| holds(a, id, ancestors)),
            FilterExpr::Not { arg } => !holds(arg, id, ancestors),
            FilterExpr::IdIn { ids } => ids.iter().any(|i| i.as_str() == id),
            FilterExpr::Under { scopes } => scopes.iter().any(|s| ancestors.contains(s)),
            other => panic!("not used by these tests: {other:?}"),
        }
    }
    let base = f.ids_in.iter().any(|i| i.as_str() == id)
        || f.container_in.iter().any(|s| ancestors.contains(s));
    base && f.condition.as_ref().is_none_or(|c| holds(c, id, ancestors))
}

#[tokio::test]
async fn migrations_run_once_and_a_newer_schema_is_refused() {
    let Some(mut db) = db().await else { return };
    assert_eq!(
        crate::migrate(&mut db.client).await.unwrap(),
        Vec::<i32>::new()
    );
    db.client
        .batch_execute("INSERT INTO tutela.schema_migration (version, name) VALUES (999, 'future')")
        .await
        .unwrap();
    assert!(matches!(
        crate::migrate(&mut db.client).await,
        Err(StoreError::SchemaTooNew(999))
    ));
    db.finish().await;
}

#[tokio::test]
async fn tm05_row_level_security_hides_other_tenants_and_everything_with_no_tenant() {
    let Some(mut db) = db().await else { return };
    let (a, ao) = tenant(&mut db.client).await;
    let (b, bo) = tenant(&mut db.client).await;
    for (t, o) in [(&a, &ao), (&b, &bo)] {
        let tx = db.client.transaction().await.unwrap();
        crate::assign(
            &tx,
            t,
            &Subject::Principal(user(1)),
            &role("reader"),
            &org(o),
            None,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // No tenant set: zero rows, even for the table owner.
    for table in ["role_assignment", "org", "tenant_rev", "scope_path"] {
        let n: i64 = db
            .client
            .query_one(&format!("SELECT count(*) FROM tutela.{table}"), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(n, 0, "{table}");
    }
    // Tenant A set: only A's rows, and no row may be written for B.
    let tx = db.client.transaction().await.unwrap();
    tx.query_one(
        "SELECT set_config('tutela.tenant_id', $1, true)",
        &[&a.tid.to_string()],
    )
    .await
    .unwrap();
    let rows = tx
        .query("SELECT tenant_id FROM tutela.role_assignment", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, &str>(0), a.tid.to_string());
    let sneak = tx
        .execute(
            "INSERT INTO tutela.org (tenant_id, org_id) VALUES ($1, $2)",
            &[
                &b.tid.to_string(),
                &OrgId::new(tutela_contracts::id::Uuid7::from_uuid(uuid::Uuid::now_v7()).unwrap())
                    .to_string(),
            ],
        )
        .await;
    assert!(
        sneak.is_err(),
        "a row for another tenant must not be written"
    );
    drop(tx);
    // The store's own reads see one tenant only.
    let la = load(&mut db.client, &a).await;
    assert_eq!(la.data.orgs, [ao].into());
    assert_eq!(la.data.bindings.len(), 1);
    // A tenant key with the right id but another issuer is unknown.
    let wrong = TenantKey::new("https://other.example.test".parse().unwrap(), a.tid);
    let tx = db.client.transaction().await.unwrap();
    assert!(matches!(
        crate::load(&tx, &wrong).await,
        Err(StoreError::UnknownTenant)
    ));
    drop(tx);
    db.finish().await;
}

#[tokio::test]
async fn every_write_bumps_the_revision_in_its_own_transaction() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    assert_eq!(load(&mut db.client, &t).await.rev, 1);
    // Rolled back: neither the change nor the bump stays.
    let tx = db.client.transaction().await.unwrap();
    let (_, rev) = crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &org(&o),
        None,
    )
    .await
    .unwrap();
    assert_eq!(rev, 2);
    tx.rollback().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert_eq!((b.rev, b.data.bindings.len()), (1, 0));
    // Committed: both.
    let tx = db.client.transaction().await.unwrap();
    let (id, rev) = crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &org(&o),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert_eq!((b.rev, b.data.bindings.len()), (rev, 1));
    assert!(id.as_str().starts_with("ra_"));
    // One assignment per (subject, scope).
    let tx = db.client.transaction().await.unwrap();
    assert!(matches!(
        crate::assign(
            &tx,
            &t,
            &Subject::Principal(user(1)),
            &role("reader"),
            &org(&o),
            None
        )
        .await,
        Err(StoreError::Exists(_))
    ));
    drop(tx);
    db.finish().await;
}

#[tokio::test]
async fn a_loaded_tenant_decides_like_the_worked_example() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let d = entry("department", "d-procurement");
    let open = entry("matter", "m-open");
    let private = entry("matter", "m-board");
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &open, &[d.clone(), org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &private, &[d.clone(), org(&o)], true)
        .await
        .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &d,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert!(b.data.private_scopes.contains(&private));
    let pdp = pdp_of(&t, &b);
    let under = |m: &PathEntry| vec![m.clone(), d.clone(), org(&o)];
    let ok = pdp
        .check(&read(&t, &user(1), "contract", "c-1", under(&open)))
        .unwrap();
    assert_eq!(ok.effect, Effect::Allow);
    let no = pdp
        .check(&read(&t, &user(1), "contract", "c-2", under(&private)))
        .unwrap();
    assert_eq!(no.effect, Effect::Deny);
    assert_eq!(no.reason.code(), "private_scope");
    // The list agrees, with the store's scope paths.
    let f = pdp
        .list_filter(
            &ListFilterRequest {
                tenant: t.clone(),
                subject: user(1),
                actors: vec![],
                action: ActionKey::parse("contract:read").unwrap(),
                at_least_revision: None,
            },
            &b.paths,
        )
        .unwrap();
    assert!(row_matches(&f, "c-1", &under(&open)));
    assert!(!row_matches(&f, "c-2", &under(&private)));
    db.finish().await;
}

#[tokio::test]
async fn tm10_scope_paths_are_current_after_a_move() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let d1 = entry("department", "d-1");
    let d2 = entry("department", "d-2");
    let p = entry("matter", "m-secret");
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d1, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &d2, &[org(&o)], false)
        .await
        .unwrap();
    // A private matter starts in d-2; the user reads all of d-1.
    crate::put_scope(&tx, &t, &p, &[d2.clone(), org(&o)], true)
        .await
        .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &d1,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let list = |b: &TenantBundle| {
        pdp_of(&t, b)
            .list_filter(
                &ListFilterRequest {
                    tenant: t.clone(),
                    subject: user(1),
                    actors: vec![],
                    action: ActionKey::parse("contract:read").unwrap(),
                    at_least_revision: None,
                },
                &b.paths,
            )
            .unwrap()
    };
    // The product moves the private matter into d-1, and its rows' ancestors
    // with it, in one transaction.
    let tx = db.client.transaction().await.unwrap();
    let rev = crate::move_scope(&tx, &t, &p, &[d1.clone(), org(&o)])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert_eq!(b.rev, rev);
    // A row in the moved matter is now under d-1 and still private: neither
    // the list nor check shows it.
    let row = [p.clone(), d1.clone(), org(&o)];
    assert!(!row_matches(&list(&b), "c-9", &row));
    let d = pdp_of(&t, &b)
        .check(&read(&t, &user(1), "contract", "c-9", row.to_vec()))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    // A row directly in d-1 is listed.
    assert!(row_matches(&list(&b), "c-1", &[d1.clone(), org(&o)]));
    db.finish().await;
}

#[tokio::test]
async fn moving_rewrites_every_path_below_and_refuses_cycles_and_depth() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let d1 = entry("department", "d-1");
    let d2 = entry("department", "d-2");
    let m = entry("matter", "m-1");
    let c = entry("contract", "c-1");
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d1, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &d2, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &m, &[d1.clone(), org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &c, &[m.clone(), d1.clone(), org(&o)], false)
        .await
        .unwrap();
    // A path that disagrees with a registered ancestor is refused.
    assert!(matches!(
        crate::put_scope(
            &tx,
            &t,
            &entry("contract", "c-2"),
            &[m.clone(), d2.clone(), org(&o)],
            false
        )
        .await,
        Err(StoreError::Invalid(_))
    ));
    // The caller rolls back after an error.
    drop(tx);
    // Set up again in one committed transaction.
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d1, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &d2, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &m, &[d1.clone(), org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &c, &[m.clone(), d1.clone(), org(&o)], false)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let tx = db.client.transaction().await.unwrap();
    crate::move_scope(&tx, &t, &m, &[d2.clone(), org(&o)])
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    use tutela_pdp::ScopePaths as _;
    assert_eq!(
        b.paths.ancestors(&t, &c).unwrap(),
        [m.clone(), d2.clone(), org(&o)]
    );
    // Under itself, directly or through a scope below it: refused.
    let tx = db.client.transaction().await.unwrap();
    assert!(matches!(
        crate::move_scope(&tx, &t, &m, &[c.clone(), m.clone(), d2.clone(), org(&o)]).await,
        Err(StoreError::Invalid(_))
    ));
    drop(tx);
    let tx = db.client.transaction().await.unwrap();
    assert!(matches!(
        crate::move_scope(&tx, &t, &m, &[c.clone(), d2.clone(), org(&o)]).await,
        Err(StoreError::Invalid(_))
    ));
    drop(tx);
    // Too deep below after the move: refused before anything is written.
    // m has c below it, so m may not get more than 31 ancestors.
    let tx = db.client.transaction().await.unwrap();
    let mut chain = vec![org(&o)];
    crate::put_scope(&tx, &t, &entry("department", "deep"), &chain, false)
        .await
        .unwrap();
    chain.insert(0, entry("department", "deep"));
    for i in 0..30 {
        let s = entry("matter", &format!("x{i}"));
        crate::put_scope(&tx, &t, &s, &chain, false).await.unwrap();
        chain.insert(0, s);
    }
    assert_eq!(chain.len(), 32);
    assert!(matches!(
        crate::move_scope(&tx, &t, &m, &chain).await,
        Err(StoreError::Invalid(_))
    ));
    // With one level less it fits: c then has exactly 32 ancestors.
    crate::move_scope(&tx, &t, &m, &chain[1..]).await.unwrap();
    drop(tx);
    db.finish().await;
}

#[tokio::test]
async fn deleting_a_scope_removes_everything_below_in_one_revision() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let d = entry("department", "d-1");
    let m = entry("matter", "m-1");
    let other = entry("department", "d-2");
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &m, &[d.clone(), org(&o)], true)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &other, &[org(&o)], false)
        .await
        .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &m,
        None,
    )
    .await
    .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(2)),
        &role("reader"),
        &other,
        None,
    )
    .await
    .unwrap();
    crate::put_field_rule(
        &tx,
        &t,
        &m,
        &"contract.title".parse().unwrap(),
        None,
        tutela_contracts::level::Level::None,
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let before = load(&mut db.client, &t).await;
    let tx = db.client.transaction().await.unwrap();
    let rev = crate::delete_scope(&tx, &t, &d).await.unwrap();
    tx.commit().await.unwrap();
    let after = load(&mut db.client, &t).await;
    assert_eq!((after.rev, rev), (before.rev + 1, before.rev + 1));
    assert!(after.data.private_scopes.is_empty());
    assert!(after.data.field_rules.is_empty());
    assert_eq!(after.data.bindings.len(), 1);
    assert_eq!(after.data.bindings[0].scope, other);
    assert_eq!(after.paths.len(), 1);
    db.finish().await;
}

#[tokio::test]
async fn group_rules_are_checked_on_every_write() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    for k in ["a", "b"] {
        crate::create_group(&tx, &t, &o, &gkey(k), "")
            .await
            .unwrap();
    }
    // Keys are unique in the tenant.
    assert!(matches!(
        crate::create_group(&tx, &t, &o, &gkey("a"), "").await,
        Err(StoreError::Exists(_))
    ));
    drop(tx);
    let tx = db.client.transaction().await.unwrap();
    for k in ["a", "b"] {
        crate::create_group(&tx, &t, &o, &gkey(k), "")
            .await
            .unwrap();
    }
    crate::add_member(&tx, &t, &gkey("a"), &Member::Group(gkey("b")), None)
        .await
        .unwrap();
    crate::add_member(&tx, &t, &gkey("b"), &Member::Principal(user(1)), None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    // A cycle is refused.
    let tx = db.client.transaction().await.unwrap();
    assert!(matches!(
        crate::add_member(&tx, &t, &gkey("b"), &Member::Group(gkey("a")), None).await,
        Err(StoreError::Refused(LoadError::GroupCycle(_)))
    ));
    drop(tx);
    // Nesting deeper than 32 is refused: a chain of 32 loads, 33 does not.
    let tx = db.client.transaction().await.unwrap();
    for i in 0..32 {
        crate::create_group(&tx, &t, &o, &gkey(&format!("c{i}")), "")
            .await
            .unwrap();
        if i > 0 {
            crate::add_member(
                &tx,
                &t,
                &gkey(&format!("c{}", i - 1)),
                &Member::Group(gkey(&format!("c{i}"))),
                None,
            )
            .await
            .unwrap();
        }
    }
    crate::create_group(&tx, &t, &o, &gkey("c32"), "")
        .await
        .unwrap();
    assert!(matches!(
        crate::add_member(&tx, &t, &gkey("c31"), &Member::Group(gkey("c32")), None).await,
        Err(StoreError::Refused(LoadError::GroupsTooDeep(_)))
    ));
    drop(tx);
    // A closure over the work limit is refused: 32 levels of 25 groups, each
    // holding the whole next level (the rows go in directly; the last link
    // goes through the store and is refused).
    let tx = db.client.transaction().await.unwrap();
    tx.query_one(
        "SELECT set_config('tutela.tenant_id', $1, true)",
        &[&t.tid.to_string()],
    )
    .await
    .unwrap();
    let tid = t.tid.to_string();
    tx.execute(
        "INSERT INTO tutela.\"group\" (tenant_id, id, org_id, key) \
         SELECT $1, 'grp_l' || l || 'g' || g, $2, 'l' || l || 'g' || g \
         FROM generate_series(0, 31) l, generate_series(0, 24) g",
        &[&tid, &o.to_string()],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO tutela.group_member (tenant_id, group_id, member_kind, member_id) \
         SELECT $1, 'grp_l' || l || 'g' || g, 'group', 'grp_l' || (l + 1) || 'g' || h \
         FROM generate_series(0, 30) l, generate_series(0, 24) g, generate_series(0, 24) h \
         WHERE NOT (l = 30 AND g = 0 AND h = 0)",
        &[&tid],
    )
    .await
    .unwrap();
    assert!(matches!(
        crate::add_member(&tx, &t, &gkey("l30g0"), &Member::Group(gkey("l31g0")), None).await,
        Err(StoreError::Refused(LoadError::GroupClosureTooLarge))
    ));
    drop(tx);
    // Deleting a group takes its assignments and its places with it.
    let tx = db.client.transaction().await.unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Group(gkey("b")),
        &role("reader"),
        &org(&o),
        None,
    )
    .await
    .unwrap();
    crate::delete_group(&tx, &t, &gkey("b")).await.unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert!(b.data.bindings.is_empty());
    assert_eq!(b.data.groups.len(), 1);
    assert!(b.data.groups[0].members.is_empty());
    db.finish().await;
}

#[tokio::test]
async fn publishing_a_manifest_bumps_every_tenant_and_records_the_change() {
    let Some(mut db) = db().await else { return };
    let (a, _) = tenant(&mut db.client).await;
    let (b, _) = tenant(&mut db.client).await;
    let app = AppName::parse("store_test").unwrap();
    let publish = |expected| crate::Publish {
        app: &app,
        source: MANIFEST,
        expected,
        class: Class::Widening,
        diff: "+ type contract",
        author: Some("test"),
        approvers: &[],
    };
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(crate::manifest(&tx, &app).await.unwrap(), None);
    let out = crate::publish_manifest(&tx, &publish(None)).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|(_, rev)| *rev == 2));
    assert_eq!(load(&mut db.client, &a).await.rev, 2);
    assert_eq!(load(&mut db.client, &b).await.rev, 2);
    let tx = db.client.transaction().await.unwrap();
    let stored = crate::manifest(&tx, &app).await.unwrap().unwrap();
    assert_eq!(stored.version, 1);
    assert_eq!(stored.digest, crate::digest(MANIFEST));
    // Compared against version 0 while version 1 is in: refused.
    assert!(matches!(
        crate::publish_manifest(&tx, &publish(None)).await,
        Err(StoreError::Exists(_))
    ));
    drop(tx);
    // Each tenant has its record.
    let tx = db.client.transaction().await.unwrap();
    tx.query_one(
        "SELECT set_config('tutela.tenant_id', $1, true)",
        &[&a.tid.to_string()],
    )
    .await
    .unwrap();
    let rows = tx
        .query("SELECT rev, class FROM tutela.model_revision", &[])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<_, &str>(1), "widening");
    drop(tx);
    db.finish().await;
}
