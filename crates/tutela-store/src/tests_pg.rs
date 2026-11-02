//! `tutela-store` against a real Postgres.
//!
//! `TUTELA_TEST_DATABASE_URL` names a server and a role that may create
//! roles and databases (for example
//! `host=127.0.0.1 port=5432 user=postgres password=postgres dbname=postgres`).
//! Each test makes its own database, owned by a role that is **not** a
//! superuser, so `FORCE ROW LEVEL SECURITY` applies to everything the test
//! does. With the variable unset, each test says so and passes, except when
//! `TUTELA_REQUIRE_DATABASE=1` (CI sets it): then a missing database fails.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::{AssignmentQuery, StoreError, StoreErrorKind, TenantBundle};
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
    assert_eq!(applied, [1, 2, 3]);
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

/// The kind of a failed call.
fn kind<T>(r: Result<T, StoreError>) -> Option<StoreErrorKind> {
    r.err().map(|e| e.kind())
}

/// The rule a refused change breaks.
fn refusal<T>(r: Result<T, StoreError>) -> Option<LoadError> {
    r.err().and_then(|e| e.refusal().cloned())
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
    assert_eq!(
        kind(crate::migrate(&mut db.client).await),
        Some(StoreErrorKind::SchemaTooNew)
    );
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
    assert_eq!(
        kind(crate::load(&tx, &wrong).await),
        Some(StoreErrorKind::UnknownTenant)
    );
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
    assert_eq!(
        kind(
            crate::assign(
                &tx,
                &t,
                &Subject::Principal(user(1)),
                &role("reader"),
                &org(&o),
                None
            )
            .await
        ),
        Some(StoreErrorKind::Exists)
    );
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
    assert_eq!(
        kind(
            crate::put_scope(
                &tx,
                &t,
                &entry("contract", "c-2"),
                &[m.clone(), d2.clone(), org(&o)],
                false
            )
            .await
        ),
        Some(StoreErrorKind::Invalid)
    );
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
    assert_eq!(
        kind(crate::move_scope(&tx, &t, &m, &[c.clone(), m.clone(), d2.clone(), org(&o)]).await),
        Some(StoreErrorKind::Invalid)
    );
    drop(tx);
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::move_scope(&tx, &t, &m, &[c.clone(), d2.clone(), org(&o)]).await),
        Some(StoreErrorKind::Invalid)
    );
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
    assert_eq!(
        kind(crate::move_scope(&tx, &t, &m, &chain).await),
        Some(StoreErrorKind::Invalid)
    );
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
    assert_eq!(
        kind(crate::create_group(&tx, &t, &o, &gkey("a"), "").await),
        Some(StoreErrorKind::Exists)
    );
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
        refusal(crate::add_member(&tx, &t, &gkey("b"), &Member::Group(gkey("a")), None).await),
        Some(LoadError::GroupCycle(_))
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
        refusal(crate::add_member(&tx, &t, &gkey("c31"), &Member::Group(gkey("c32")), None).await),
        Some(LoadError::GroupsTooDeep(_))
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
        refusal(
            crate::add_member(&tx, &t, &gkey("l30g0"), &Member::Group(gkey("l31g0")), None).await
        ),
        Some(LoadError::GroupClosureTooLarge)
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
async fn a_schema_with_two_apps_has_no_applied_manifest_to_guess() {
    let Some(mut db) = db().await else { return };
    let tx = db.client.transaction().await.unwrap();
    for app in ["one", "two"] {
        let app = tutela_pdp::model::AppName::parse(app).unwrap();
        crate::publish_manifest(
            &tx,
            &crate::Publish {
                app: &app,
                source: MANIFEST,
                expected: None,
                class: Class::Neutral,
                diff: "",
                author: None,
                approvers: &[],
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(
        kind(crate::applied_manifest(&tx).await),
        Some(StoreErrorKind::Invalid)
    );
    drop(tx);
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
    assert_eq!(crate::applied_manifest(&tx).await.unwrap(), None);
    let out = crate::publish_manifest(&tx, &publish(None)).await.unwrap();
    assert_eq!(
        crate::applied_manifest(&tx).await.unwrap(),
        crate::manifest(&tx, &app).await.unwrap()
    );
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
    assert_eq!(
        kind(crate::publish_manifest(&tx, &publish(None)).await),
        Some(StoreErrorKind::Exists)
    );
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

/// A transaction belongs to one tenant: a store call with another key
/// fails, and never switches the transaction.
#[tokio::test]
async fn a_transaction_refuses_a_second_tenant() {
    let Some(mut db) = db().await else { return };
    let (a, _) = tenant(&mut db.client).await;
    let (b, _) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    crate::enter(&tx, &a).await.unwrap();
    crate::enter(&tx, &a).await.unwrap();
    assert_eq!(
        kind(crate::load(&tx, &b).await),
        Some(StoreErrorKind::TenantMismatch)
    );
    assert_eq!(
        kind(crate::add_org(&tx, &b).await),
        Some(StoreErrorKind::TenantMismatch)
    );
    drop(tx);
    // A later transaction on the same connection is free again.
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(crate::rev(&tx, &b).await.unwrap(), 1);
    drop(tx);
    db.finish().await;
}

/// A driver error stays in `source()`, its SQLSTATE is readable, and no
/// driver type is in the public error (#43).
#[tokio::test]
async fn a_database_error_keeps_its_cause_and_its_sqlstate() {
    let Some(mut db) = db().await else { return };
    let (t, _) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    tx.batch_execute("SELECT * FROM no_such_table")
        .await
        .unwrap_err();
    // The failed statement aborted the transaction: the next call fails.
    let e = crate::rev(&tx, &t).await.unwrap_err();
    assert_eq!(e.kind(), StoreErrorKind::Database);
    assert_eq!(e.sqlstate(), Some("25P02"));
    assert_eq!(e.to_string(), "database error");
    assert!(std::error::Error::source(&e).is_some());
    drop(tx);
    db.finish().await;
}

/// Moves an assignment's expiry into the past, as time would. The row's
/// tenant is entered so forced row-level security lets the update through.
async fn pass_expiry(c: &mut Client, t: &TenantKey, id: &tutela_contracts::decision::RuleId) {
    let tx = c.transaction().await.unwrap();
    crate::enter(&tx, t).await.unwrap();
    let n = tx
        .execute(
            "UPDATE tutela.role_assignment SET expires_at = now() - interval '1 second' \
             WHERE tenant_id = $1 AND id = $2",
            &[&t.tid.to_string(), &id.as_str()],
        )
        .await
        .unwrap();
    assert_eq!(n, 1);
    tx.commit().await.unwrap();
}

fn in_an_hour() -> SystemTime {
    SystemTime::now() + Duration::from_secs(3600)
}

/// An assignment with an expiry counts until it passes. Then it stops
/// counting at once, and the sweep removes it and bumps the revision once.
#[tokio::test]
async fn an_assignment_counts_until_it_expires_and_the_sweep_bumps_the_revision() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let (other, other_org) = tenant(&mut db.client).await;
    let until = in_an_hour();
    let tx = db.client.transaction().await.unwrap();
    let (rule, rev) = crate::assign_until(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &org(&o),
        None,
        until,
    )
    .await
    .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(2)),
        &role("reader"),
        &org(&o),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let tx = db.client.transaction().await.unwrap();
    let (other_rule, _) = crate::assign_until(
        &tx,
        &other,
        &Subject::Principal(user(1)),
        &role("reader"),
        &org(&other_org),
        None,
        until,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // It counts, and the bundle says how long the view is good.
    let before = load(&mut db.client, &t).await;
    assert_eq!(before.rev, rev + 1);
    assert_eq!(before.data.bindings.len(), 2);
    let next = before.next_expiry.unwrap();
    let off = next.duration_since(until).unwrap_or_else(|e| e.duration());
    assert!(off < Duration::from_millis(2), "{off:?}");

    // Nothing has expired: no bump.
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(crate::expire_assignments(&tx, &t).await.unwrap(), None);
    tx.commit().await.unwrap();
    assert_eq!(load(&mut db.client, &t).await.rev, before.rev);

    pass_expiry(&mut db.client, &t, &rule).await;

    // It stopped counting before any sweep. Failing closed does not wait,
    // and the revision has not moved yet.
    let after = load(&mut db.client, &t).await;
    assert_eq!(after.rev, before.rev);
    assert_eq!(after.data.bindings.len(), 1);
    assert_eq!(after.next_expiry, None);
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::assignment(&tx, &t, &rule).await),
        Some(StoreErrorKind::NotFound)
    );
    assert_eq!(crate::assignments_for(&tx, &t, &user(1)).await.unwrap(), []);
    drop(tx);

    // The sweep removes it and bumps once. A second sweep finds nothing.
    let tx = db.client.transaction().await.unwrap();
    let gone = crate::expire_assignments(&tx, &t).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_eq!(gone.rev, before.rev + 1);
    assert_eq!(gone.assignments.len(), 1);
    assert_eq!(gone.assignments[0].id, rule);
    assert_eq!(gone.assignments[0].subject, Subject::Principal(user(1)));
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(crate::expire_assignments(&tx, &t).await.unwrap(), None);
    tx.commit().await.unwrap();
    assert_eq!(load(&mut db.client, &t).await.rev, gone.rev);

    // The other tenant's row, with the same expiry, was not touched.
    let theirs = load(&mut db.client, &other).await;
    assert_eq!(theirs.data.bindings.len(), 1);
    assert_eq!(theirs.data.bindings[0].id, other_rule);
    db.finish().await;
}

/// Two replicas sweep at once: one expiry is one revision.
#[tokio::test]
async fn two_sweeps_at_once_make_one_revision() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    let (rule, _) = crate::assign_until(
        &tx,
        &t,
        &Subject::Principal(user(1)),
        &role("reader"),
        &org(&o),
        None,
        in_an_hour(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    pass_expiry(&mut db.client, &t, &rule).await;
    let rev = load(&mut db.client, &t).await.rev;

    let url = with(&base_url().unwrap(), &db.name, OWNER, OWNER_PASSWORD);
    let mut second = connect(&url).await;
    let first_tx = db.client.transaction().await.unwrap();
    let gone = crate::expire_assignments(&first_tx, &t)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(gone.rev, rev + 1);
    // The second sweep saw the row before the first commits, then waits on
    // the revision row.
    let t2 = t.clone();
    let waiting = tokio::spawn(async move {
        let tx = second.transaction().await.unwrap();
        let r = crate::expire_assignments(&tx, &t2).await.unwrap();
        tx.commit().await.unwrap();
        r
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    first_tx.commit().await.unwrap();
    assert_eq!(waiting.await.unwrap(), None);
    assert_eq!(load(&mut db.client, &t).await.rev, rev + 1);
    db.finish().await;
}

#[tokio::test]
async fn an_expiry_must_be_ahead_and_can_change() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let subject = Subject::Principal(user(1));

    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(
            crate::assign_until(
                &tx,
                &t,
                &subject,
                &role("reader"),
                &org(&o),
                None,
                SystemTime::now() - Duration::from_secs(5),
            )
            .await
        ),
        Some(StoreErrorKind::Invalid)
    );
    drop(tx);

    let tx = db.client.transaction().await.unwrap();
    let (rule, rev) = crate::assign_until(
        &tx,
        &t,
        &subject,
        &role("reader"),
        &org(&o),
        None,
        in_an_hour(),
    )
    .await
    .unwrap();
    // Permanent now: each change is a revision.
    let made_permanent = crate::set_assignment_expiry(&tx, &t, &rule, None)
        .await
        .unwrap();
    assert_eq!(made_permanent, rev + 1);
    assert_eq!(
        crate::assignment(&tx, &t, &rule).await.unwrap().expires_at,
        None
    );
    assert_eq!(
        kind(
            crate::set_assignment_expiry(
                &tx,
                &t,
                &rule,
                Some(SystemTime::now() - Duration::from_secs(5)),
            )
            .await
        ),
        Some(StoreErrorKind::Invalid)
    );
    drop(tx);

    // An assignment past its expiry does not hold the place, and cannot be
    // brought back.
    let tx = db.client.transaction().await.unwrap();
    let (rule, _) = crate::assign_until(
        &tx,
        &t,
        &subject,
        &role("reader"),
        &org(&o),
        None,
        in_an_hour(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    pass_expiry(&mut db.client, &t, &rule).await;
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::set_assignment_expiry(&tx, &t, &rule, None).await),
        Some(StoreErrorKind::NotFound)
    );
    drop(tx);
    let tx = db.client.transaction().await.unwrap();
    let (again, _) = crate::assign(&tx, &t, &subject, &role("reader"), &org(&o), None)
        .await
        .unwrap();
    assert_ne!(again, rule);
    tx.commit().await.unwrap();
    assert_eq!(load(&mut db.client, &t).await.data.bindings.len(), 1);
    db.finish().await;
}

#[tokio::test]
async fn assignments_and_groups_read_back_as_they_were_written() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    crate::create_group(&tx, &t, &o, &gkey("staff"), "Staff")
        .await
        .unwrap();
    crate::add_member(
        &tx,
        &t,
        &gkey("staff"),
        &Member::Principal(user(1)),
        Some(&user(9)),
    )
    .await
    .unwrap();
    let scope = entry("department", "d1");
    crate::put_scope(&tx, &t, &scope, &[org(&o)], false)
        .await
        .unwrap();
    let group = Subject::Group(gkey("staff"));
    let (by_group, rev) = crate::assign(&tx, &t, &group, &role("reader"), &scope, Some(&user(9)))
        .await
        .unwrap();
    for n in 2..5 {
        crate::assign(
            &tx,
            &t,
            &Subject::Principal(user(n)),
            &role("reader"),
            &org(&o),
            None,
        )
        .await
        .unwrap();
    }

    let one = crate::assignment(&tx, &t, &by_group).await.unwrap();
    assert_eq!(one.subject, group);
    assert_eq!(one.role, role("reader"));
    assert_eq!(one.scope, scope);
    assert_eq!(one.granted_by, Some(user(9)));
    assert_eq!(one.expires_at, None);
    assert_eq!(one.rev, rev);

    let query = |q: AssignmentQuery<'static>| q;
    let all = crate::assignments(&tx, &t, &query(AssignmentQuery::default()))
        .await
        .unwrap();
    assert_eq!(all.len(), 4);
    let ids: Vec<_> = all.iter().map(|a| a.id.clone()).collect();
    let mut sorted = ids.clone();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(ids, sorted);

    let first = crate::assignments(
        &tx,
        &t,
        &AssignmentQuery {
            limit: Some(3),
            ..AssignmentQuery::default()
        },
    )
    .await
    .unwrap();
    let rest = crate::assignments(
        &tx,
        &t,
        &AssignmentQuery {
            after: Some(&first[2].id),
            ..AssignmentQuery::default()
        },
    )
    .await
    .unwrap();
    assert_eq!((first.len(), rest.len()), (3, 1));
    assert_eq!(rest[0].id, all[3].id);

    let at = crate::assignments(
        &tx,
        &t,
        &AssignmentQuery {
            scope: Some(&scope),
            ..AssignmentQuery::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(at.len(), 1);
    let of = crate::assignments(
        &tx,
        &t,
        &AssignmentQuery {
            subject: Some(&group),
            ..AssignmentQuery::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(of[0].id, by_group);
    assert_eq!(
        kind(
            crate::assignments(
                &tx,
                &t,
                &AssignmentQuery {
                    limit: Some(crate::MAX_PAGE + 1),
                    ..AssignmentQuery::default()
                },
            )
            .await
        ),
        Some(StoreErrorKind::Invalid)
    );

    let groups = crate::groups(&tx, &t).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!((groups[0].key.clone(), groups[0].org), (gkey("staff"), o));
    assert_eq!(groups[0].name, "Staff");
    assert_eq!(
        crate::group_members(&tx, &t, &gkey("staff")).await.unwrap(),
        [Member::Principal(user(1))]
    );
    drop(tx);
    db.finish().await;
}

/// The closures are read at query time, across nesting, and agree with a
/// plain walk of the same random group graph.
#[tokio::test]
async fn the_group_closures_agree_with_a_walk_of_the_edges() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let (other, other_org) = tenant(&mut db.client).await;
    const GROUPS: usize = 12;
    const USERS: u32 = 8;
    let name = |g: usize| gkey(&format!("g{g}"));
    let mut seed = 0x5eed_u64;
    let mut next = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % (n as u64)).unwrap()
    };
    let tx = db.client.transaction().await.unwrap();
    for g in 0..GROUPS {
        crate::create_group(&tx, &t, &o, &name(g), "")
            .await
            .unwrap();
    }
    // Edges go from a higher number into a lower one, so there is no cycle.
    let mut in_group: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for g in 1..GROUPS {
        for _ in 0..2 {
            let parent = next(g);
            if in_group.entry(g).or_default().insert(parent) {
                crate::add_member(&tx, &t, &name(parent), &Member::Group(name(g)), None)
                    .await
                    .unwrap();
            }
        }
    }
    let mut direct: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    for u in 0..USERS {
        for _ in 0..2 {
            let g = next(GROUPS);
            if direct.entry(u).or_default().insert(g) {
                crate::add_member(&tx, &t, &name(g), &Member::Principal(user(u)), None)
                    .await
                    .unwrap();
            }
        }
    }
    tx.commit().await.unwrap();

    // Another tenant with the same keys and the same user.
    let tx = db.client.transaction().await.unwrap();
    crate::create_group(&tx, &other, &other_org, &name(GROUPS), "")
        .await
        .unwrap();
    crate::add_member(
        &tx,
        &other,
        &name(GROUPS),
        &Member::Principal(user(0)),
        None,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let up = |start: &BTreeSet<usize>| {
        let mut seen = start.clone();
        let mut todo: Vec<usize> = start.iter().copied().collect();
        while let Some(g) = todo.pop() {
            for &p in in_group.get(&g).into_iter().flatten() {
                if seen.insert(p) {
                    todo.push(p);
                }
            }
        }
        seen
    };
    let tx = db.client.transaction().await.unwrap();
    let mut members: BTreeMap<usize, BTreeSet<Principal>> = BTreeMap::new();
    for u in 0..USERS {
        let want = up(&direct[&u]);
        for &g in &want {
            members.entry(g).or_default().insert(user(u));
        }
        let want: BTreeSet<GroupKey> = want.into_iter().map(name).collect();
        assert_eq!(crate::groups_of(&tx, &t, &user(u)).await.unwrap(), want);
    }
    for g in 0..GROUPS {
        assert_eq!(
            crate::members_of(&tx, &t, &name(g)).await.unwrap(),
            members.remove(&g).unwrap_or_default(),
            "group {g}"
        );
    }
    assert_eq!(
        kind(crate::members_of(&tx, &t, &name(GROUPS)).await),
        Some(StoreErrorKind::NotFound)
    );
    drop(tx);
    db.finish().await;
}

#[tokio::test]
async fn the_path_closure_reads_both_ways_and_stops_at_the_tenant() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let (other, other_org) = tenant(&mut db.client).await;
    let d = entry("department", "d1");
    let m = entry("matter", "m1");
    let c = entry("contract", "c1");
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &t, &d, &[org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &m, &[d.clone(), org(&o)], false)
        .await
        .unwrap();
    crate::put_scope(&tx, &t, &c, &[m.clone(), d.clone(), org(&o)], false)
        .await
        .unwrap();
    assert_eq!(
        crate::ancestors(&tx, &t, &c).await.unwrap(),
        Some(vec![m.clone(), d.clone(), org(&o)])
    );
    assert_eq!(
        crate::ancestors(&tx, &t, &entry("matter", "nope"))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        crate::scopes_below(&tx, &t, &d).await.unwrap(),
        [c.clone(), m.clone()]
    );
    assert_eq!(
        crate::scopes_below(&tx, &t, &org(&o)).await.unwrap().len(),
        3
    );
    tx.commit().await.unwrap();
    // Another tenant with the same scope ids sees only its own.
    let tx = db.client.transaction().await.unwrap();
    crate::put_scope(&tx, &other, &d, &[org(&other_org)], false)
        .await
        .unwrap();
    assert_eq!(crate::scopes_below(&tx, &other, &d).await.unwrap(), []);
    drop(tx);
    db.finish().await;
}

/// Deleting a principal takes its assignments and memberships in one
/// revision (PERMISSION-MODEL.md 6.4), and leaves everyone else alone.
#[tokio::test]
async fn removing_a_principal_takes_its_bindings_in_one_revision() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    crate::create_group(&tx, &t, &o, &gkey("staff"), "")
        .await
        .unwrap();
    for n in [1, 2] {
        crate::add_member(&tx, &t, &gkey("staff"), &Member::Principal(user(n)), None)
            .await
            .unwrap();
        crate::assign(
            &tx,
            &t,
            &Subject::Principal(user(n)),
            &role("reader"),
            &org(&o),
            None,
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let rev = load(&mut db.client, &t).await.rev;
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        crate::remove_principal(&tx, &t, &user(1)).await.unwrap(),
        rev + 1
    );
    assert_eq!(
        crate::groups_of(&tx, &t, &user(1)).await.unwrap(),
        BTreeSet::new()
    );
    assert_eq!(crate::assignments_for(&tx, &t, &user(1)).await.unwrap(), []);
    assert_eq!(crate::groups_of(&tx, &t, &user(2)).await.unwrap().len(), 1);
    assert_eq!(
        crate::assignments_for(&tx, &t, &user(2))
            .await
            .unwrap()
            .len(),
        1
    );
    tx.commit().await.unwrap();
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::remove_principal(&tx, &t, &user(1)).await),
        Some(StoreErrorKind::NotFound)
    );
    drop(tx);
    db.finish().await;
}

/// What applies to a principal: its own, and through nested groups.
#[tokio::test]
async fn assignments_for_a_principal_come_through_its_groups() {
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let tx = db.client.transaction().await.unwrap();
    crate::create_group(&tx, &t, &o, &gkey("outer"), "")
        .await
        .unwrap();
    crate::create_group(&tx, &t, &o, &gkey("inner"), "")
        .await
        .unwrap();
    crate::add_member(&tx, &t, &gkey("outer"), &Member::Group(gkey("inner")), None)
        .await
        .unwrap();
    crate::add_member(&tx, &t, &gkey("inner"), &Member::Principal(user(1)), None)
        .await
        .unwrap();
    let d = entry("department", "d1");
    crate::put_scope(&tx, &t, &d, &[org(&o)], false)
        .await
        .unwrap();
    crate::assign(
        &tx,
        &t,
        &Subject::Group(gkey("outer")),
        &role("reader"),
        &org(&o),
        None,
    )
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
    crate::assign(
        &tx,
        &t,
        &Subject::Principal(user(2)),
        &role("reader"),
        &d,
        None,
    )
    .await
    .unwrap();
    let mine = crate::assignments_for(&tx, &t, &user(1)).await.unwrap();
    let scopes: BTreeSet<_> = mine.iter().map(|a| a.scope.clone()).collect();
    assert_eq!(scopes, BTreeSet::from([d, org(&o)]));
    drop(tx);
    db.finish().await;
}

#[tokio::test]
async fn boundary_rules_are_stored_with_a_revision_and_keep_the_private_flag() {
    use tutela_pdp::{BoundaryRule, LinksFrom, MoveRule, OnLooser};
    let Some(mut db) = db().await else { return };
    let (t, o) = tenant(&mut db.client).await;
    let scope = entry("project", "p-1");
    let rule = BoundaryRule {
        moves_out: Some(MoveRule::Owners),
        moves_in: Some(MoveRule::Nobody),
        on_looser: Some(OnLooser::Block),
        links_from: Some(LinksFrom::Team),
    };
    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::set_boundary(&tx, &t, &scope, &rule).await),
        Some(StoreErrorKind::NotFound)
    );
    tx.rollback().await.unwrap();

    let tx = db.client.transaction().await.unwrap();
    assert_eq!(
        kind(crate::set_boundary(&tx, &t, &org(&o), &rule).await),
        Some(StoreErrorKind::Invalid)
    );
    tx.rollback().await.unwrap();

    let tx = db.client.transaction().await.unwrap();
    let before = crate::put_scope(&tx, &t, &scope, &[org(&o)], true)
        .await
        .unwrap();
    let after = crate::set_boundary(&tx, &t, &scope, &rule).await.unwrap();
    assert_eq!(after, before + 1);
    tx.commit().await.unwrap();

    let b = load(&mut db.client, &t).await;
    assert_eq!(b.data.boundaries.get(&scope), Some(&rule));
    assert!(b.data.private_scopes.contains(&scope));

    // Clearing the rules keeps the flag, and an empty rule is no rule.
    let tx = db.client.transaction().await.unwrap();
    crate::set_boundary(&tx, &t, &scope, &BoundaryRule::default())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let b = load(&mut db.client, &t).await;
    assert!(b.data.boundaries.is_empty());
    assert!(b.data.private_scopes.contains(&scope));
    db.finish().await;
}
