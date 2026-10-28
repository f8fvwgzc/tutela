//! The decision cache, and the SQL adapter against a real Postgres: the
//! rows the SQL returns are exactly the rows `check` allows.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use tokio_postgres::NoTls;
use tutela_contracts::decision::Effect;
use tutela_contracts::keys::ActionKey;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{OrgId, TenantKey};
use tutela_pdp::model::{Model, RoleKey};
use tutela_pdp::{
    AttrValue, Attrs, Binding, CheckRequest, ListFilterRequest, PathEntry, Pdp, ResourceRef,
    ScopePathError, ScopePaths, Subject, TenantData,
};

use crate::cache::CachedPdp;
use crate::sql::{self, Columns, SqlError};

const MANIFEST: &str = r#"
version = 1
[app]
name = "sdk_test"
[types.project]
parent = "org"
container = true
[types.item]
parent = "project"
[types.item.fields]
status = { sensitivity = "internal", grants_access = true }
owner  = { sensitivity = "internal", type = "principal", grants_access = true }
title  = { sensitivity = "internal" }
[roles.reader]
grants = { project = "read", item = "read" }
[[conditions]]
role = "reader"
type = "item"
when = { not = { eq = { field = "status", value = "secret" } } }
else = "none"
[roles.mine]
grants = { project = "read", item = "read" }
[[conditions]]
role = "mine"
type = "item"
when = { is_principal = "owner" }
else = "none"
"#;

fn user(n: u32) -> Principal {
    format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}")
        .parse()
        .unwrap()
}
fn entry(t: &str, id: &str) -> PathEntry {
    PathEntry::new(t.parse().unwrap(), id.parse().unwrap())
}
fn tenant() -> TenantKey {
    TenantKey::new(
        "https://auth.example.test".parse().unwrap(),
        "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".parse().unwrap(),
    )
}
fn org_id() -> OrgId {
    "org_0193a1b2-c3d4-7f00-9a00-000000000002".parse().unwrap()
}
fn org() -> PathEntry {
    entry("org", &org_id().to_string())
}

/// (id, project, status, owner)
fn rows() -> Vec<(
    &'static str,
    &'static str,
    Option<&'static str>,
    Option<u32>,
)> {
    vec![
        ("i1", "p1", Some("open"), Some(2)),
        ("i2", "p1", Some("secret"), Some(2)),
        ("i3", "p1", None, None),
        ("i4", "p1", Some("secret"), Some(3)),
        ("i5", "p2", Some("open"), Some(2)),
        ("i6", "p2", None, Some(3)),
        ("i7", "p3", Some("secret"), None),
        ("i8", "p3", Some("open"), Some(2)),
    ]
}

fn data() -> TenantData {
    let b = |id: &str, p: Principal, role: &str, scope: PathEntry| Binding {
        id: id.parse().unwrap(),
        subject: Subject::Principal(p),
        role: RoleKey::parse(role).unwrap(),
        scope,
    };
    TenantData {
        orgs: [org_id()].into(),
        bindings: vec![
            b("ra_1", user(1), "reader", org()),
            b("ra_2", user(2), "mine", org()),
            b("ra_3", user(3), "reader", entry("project", "p1")),
            b("ra_4", user(4), "reader", entry("project", "p2")),
        ],
        groups: vec![],
        private_scopes: [entry("project", "p2")].into(),
        field_rules: vec![],
    }
}

struct Paths;
impl ScopePaths for Paths {
    fn ancestors(&self, _: &TenantKey, s: &PathEntry) -> Result<Vec<PathEntry>, ScopePathError> {
        match s.type_name.as_str() {
            "project" => Ok(vec![org()]),
            _ => Err(ScopePathError::NotFound),
        }
    }
}

fn pdp() -> Pdp {
    let mut p = Pdp::new();
    p.load(
        tenant(),
        7,
        Arc::new(Model::from_toml(MANIFEST).unwrap()),
        data(),
    )
    .unwrap();
    p
}

fn check_req(
    who: &Principal,
    id: &str,
    project: &str,
    status: Option<&str>,
    owner: Option<u32>,
) -> CheckRequest {
    let mut attrs = Attrs::new();
    attrs.insert(
        "status".parse().unwrap(),
        status.map_or(AttrValue::Null, |s| AttrValue::String(s.into())),
    );
    attrs.insert(
        "owner".parse().unwrap(),
        owner.map_or(AttrValue::Null, |n| AttrValue::String(user(n).to_string())),
    );
    CheckRequest {
        tenant: tenant(),
        subject: who.clone(),
        actors: vec![],
        action: ActionKey::parse("item:read").unwrap(),
        resource: ResourceRef {
            type_name: "item".parse().unwrap(),
            id: id.parse().unwrap(),
            path: vec![entry("project", project), org()],
            attrs,
        },
        fields: None,
        at_least_revision: None,
    }
}

#[test]
fn the_cache_answers_repeats_and_clears_on_every_load() {
    let c = CachedPdp::new(100);
    let model = Arc::new(Model::from_toml(MANIFEST).unwrap());
    c.load(tenant(), 7, Arc::clone(&model), data()).unwrap();
    let r = check_req(&user(1), "i1", "p1", Some("open"), None);
    let first = c.check(&r).unwrap();
    assert_eq!(c.check(&r).unwrap(), first);
    assert_eq!(c.cached(), 1);
    // A reload at the same revision (a retry) may carry other data: cleared.
    let mut fewer = data();
    fewer.bindings.retain(|b| b.id.as_str() != "ra_1");
    c.load(tenant(), 7, model, fewer).unwrap();
    assert_eq!(c.cached(), 0);
    assert_eq!(c.check(&r).unwrap().effect, Effect::Deny);
    // Errors are not cached.
    let mut bad = r.clone();
    bad.resource.attrs.remove(&"status".parse().unwrap());
    assert!(c.check(&bad).is_err());
    assert_eq!(c.cached(), 1);
    // Full: cleared, then filled again.
    let small = CachedPdp::new(1);
    small
        .load(
            tenant(),
            7,
            Arc::new(Model::from_toml(MANIFEST).unwrap()),
            data(),
        )
        .unwrap();
    small.check(&r).unwrap();
    small
        .check(&check_req(&user(3), "i1", "p1", Some("open"), None))
        .unwrap();
    assert_eq!(small.cached(), 1);
}

fn columns() -> Columns {
    Columns {
        table: "item".into(),
        tenant_iss: "tenant_iss".into(),
        tenant_tid: "tenant_tid".into(),
        id: "id".into(),
        ancestors: "ancestors".into(),
        fields: HashMap::from([
            ("status".parse().unwrap(), "status".into()),
            ("owner".parse().unwrap(), "owner".into()),
        ]),
    }
}

#[test]
fn column_names_are_identifiers_and_fields_must_be_mapped() {
    let f = pdp()
        .list_filter(
            &ListFilterRequest {
                tenant: tenant(),
                subject: user(1),
                actors: vec![],
                action: ActionKey::parse("item:read").unwrap(),
                at_least_revision: None,
            },
            &Paths,
        )
        .unwrap();
    let (sql, params) = sql::where_clause(&f, &columns(), 1).unwrap();
    assert!(sql.contains("(NOT coalesce(\"status\" = $"), "{sql}");
    assert!(
        !sql.contains("secret"),
        "values are bound, never spliced: {sql}"
    );
    assert!(params.contains(&sql::Param::Text("secret".into())));
    let mut evil = columns();
    evil.ancestors = "ancestors; DROP TABLE item".into();
    assert!(matches!(
        sql::where_clause(&f, &evil, 1),
        Err(SqlError::Column(_))
    ));
    let mut unmapped = columns();
    unmapped.fields.clear();
    assert!(matches!(
        sql::where_clause(&f, &unmapped, 1),
        Err(SqlError::UnmappedField(_))
    ));
}

#[tokio::test]
async fn tm10_the_sql_lists_exactly_the_rows_check_allows() {
    let Some(base) = std::env::var("TUTELA_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        assert!(
            std::env::var("TUTELA_REQUIRE_DATABASE").as_deref() != Ok("1"),
            "TUTELA_REQUIRE_DATABASE=1 but TUTELA_TEST_DATABASE_URL is not set"
        );
        eprintln!("skipped: set TUTELA_TEST_DATABASE_URL to run the SQL adapter test");
        return;
    };
    let (mut client, conn) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(
        "CREATE TEMP TABLE item (tenant_iss text, tenant_tid text, id text, ancestors text[], status text, owner text)",
    )
    .await
    .unwrap();
    let t = tenant();
    for (id, project, status, owner) in rows() {
        let ancestors = vec![format!("project:{project}"), format!("org:{}", org_id())];
        let owner = owner.map(|n| user(n).to_string());
        for (iss, tid) in [
            (t.iss.as_str().to_owned(), t.tid.to_string()),
            // The same ids in another tenant: never listed.
            ("https://other.example.test".to_owned(), t.tid.to_string()),
        ] {
            tx.execute(
                "INSERT INTO item VALUES ($1, $2, $3, $4, $5, $6)",
                &[&iss, &tid, &id, &ancestors, &status, &owner],
            )
            .await
            .unwrap();
        }
    }
    let pdp = pdp();
    for n in 1..=5 {
        let who = user(n);
        let f = pdp
            .list_filter(
                &ListFilterRequest {
                    tenant: t.clone(),
                    subject: who.clone(),
                    actors: vec![],
                    action: ActionKey::parse("item:read").unwrap(),
                    at_least_revision: None,
                },
                &Paths,
            )
            .unwrap();
        let listed: BTreeSet<String> = sql::ids(&tx, &f, &columns(), 5_000)
            .await
            .unwrap()
            .into_iter()
            .collect();
        let allowed: BTreeSet<String> = rows()
            .into_iter()
            .filter(|(id, p, s, o)| {
                pdp.check(&check_req(&who, id, p, *s, *o)).unwrap().effect == Effect::Allow
            })
            .map(|(id, ..)| id.to_owned())
            .collect();
        assert_eq!(listed, allowed, "user {n}");
        let count = sql::count(&tx, &f, &columns(), 5_000).await.unwrap();
        assert_eq!(
            usize::try_from(count).unwrap(),
            allowed.len(),
            "user {n}: the count leaks nothing"
        );
    }
    // A slow query hits the statement timeout: an error, never a partial list.
    tx.batch_execute(
        "CREATE TEMP VIEW slow AS SELECT * FROM item WHERE (SELECT pg_sleep(0.3)) IS NOT NULL",
    )
    .await
    .unwrap();
    let f = pdp
        .list_filter(
            &ListFilterRequest {
                tenant: t,
                subject: user(1),
                actors: vec![],
                action: ActionKey::parse("item:read").unwrap(),
                at_least_revision: None,
            },
            &Paths,
        )
        .unwrap();
    let mut slow = columns();
    slow.table = "slow".into();
    assert!(matches!(
        sql::ids(&tx, &f, &slow, 50).await,
        Err(SqlError::Query(_))
    ));
}
