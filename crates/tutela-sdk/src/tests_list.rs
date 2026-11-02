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
use crate::sql::{self, Columns, SqlErrorKind};

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
    assert_eq!(
        sql::where_clause(&f, &evil, 1).unwrap_err().kind(),
        SqlErrorKind::Column
    );
    let mut unmapped = columns();
    unmapped.fields.clear();
    assert_eq!(
        sql::where_clause(&f, &unmapped, 1).unwrap_err().kind(),
        SqlErrorKind::UnmappedField
    );
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
    let err = sql::ids(&tx, &f, &slow, 50).await.unwrap_err();
    assert_eq!(err.kind(), SqlErrorKind::Query);
    assert_eq!(err.sqlstate(), Some("57014"));
    // The text leaves the cause to `source()`, so a chain shows it once.
    assert_eq!(err.to_string(), "the list query failed");
    assert!(std::error::Error::source(&err).is_some());
}

/// ADR-0016: the grouped SQL lists exactly the rows the term-by-term SQL
/// lists, on random rows with nulls and random filters of every shape.
#[tokio::test]
async fn grouped_terms_list_the_same_rows_as_term_by_term() {
    use tutela_contracts::keys::FieldName;
    use tutela_pdp::{FilterExpr as E, FilterValue as V, ListFilter};
    let Some(base) = std::env::var("TUTELA_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.is_empty())
    else {
        assert!(std::env::var("TUTELA_REQUIRE_DATABASE").as_deref() != Ok("1"));
        eprintln!("skipped: set TUTELA_TEST_DATABASE_URL");
        return;
    };
    let (mut client, conn) = tokio_postgres::connect(&base, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let tx = client.transaction().await.unwrap();
    tx.batch_execute(
        "CREATE TEMP TABLE eq_item (tenant_iss text, tenant_tid text, id text, ancestors text[],
            status text, owner text, prio bigint, flag boolean, labels text[]);
         INSERT INTO eq_item
         SELECT 'https://auth.example.test', 'ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b', 'r' || n,
                ARRAY['project:p' || (n % 30), 'department:d' || (n % 3), 'org:o'],
                CASE WHEN n % 4 = 0 THEN NULL ELSE 's' || (n % 3) END,
                CASE WHEN n % 5 = 0 THEN NULL ELSE 'u' || (n % 2) END,
                CASE WHEN n % 6 = 0 THEN NULL ELSE n % 3 END,
                CASE WHEN n % 7 = 0 THEN NULL ELSE n % 2 = 0 END,
                CASE WHEN n % 3 = 0 THEN NULL ELSE ARRAY['l' || (n % 4)] END
         FROM generate_series(0, 599) n;",
    )
    .await
    .unwrap();
    let mut cols = columns();
    cols.table = "eq_item".into();
    for (f, c) in [("prio", "prio"), ("flag", "flag"), ("labels", "labels")] {
        cols.fields.insert(f.parse().unwrap(), c.into());
    }
    let fname = |s: &str| FieldName::parse(s).unwrap();
    let mut seed = 0x5eed_u64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let p = |i: u64| entry("project", &format!("p{i}"));
    let d = |i: u64| entry("department", &format!("d{i}"));
    let s = |i: u64| V::String(format!("s{i}"));
    let mut grouped_seen = 0;
    for _ in 0..80 {
        let mut args = Vec::new();
        for _ in 0..(4 + rnd(40)) {
            let (a, b) = (rnd(30), rnd(3));
            args.push(match rnd(9) {
                0 => E::And {
                    args: vec![
                        E::Under { scopes: vec![p(a)] },
                        E::Not {
                            arg: Box::new(E::Eq {
                                attr: fname("status"),
                                value: s(b),
                            }),
                        },
                    ],
                },
                1 => E::And {
                    args: vec![
                        E::Under {
                            scopes: vec![p(a), d(b)],
                        },
                        E::Eq {
                            attr: fname("prio"),
                            value: V::Integer(i64::try_from(b).unwrap()),
                        },
                    ],
                },
                2 => E::And {
                    args: vec![
                        E::Under { scopes: vec![p(a)] },
                        E::And {
                            args: vec![
                                E::Eq {
                                    attr: fname("flag"),
                                    value: V::Boolean(b == 0),
                                },
                                E::Not {
                                    arg: Box::new(E::IsNull {
                                        attr: fname("owner"),
                                    }),
                                },
                            ],
                        },
                    ],
                },
                3 => E::And {
                    args: vec![
                        E::Under { scopes: vec![d(b)] },
                        E::Contains {
                            attr: fname("labels"),
                            value: format!("l{}", a % 4),
                        },
                    ],
                },
                4 => E::And {
                    args: vec![
                        E::Under { scopes: vec![p(a)] },
                        E::Ne {
                            attr: fname("status"),
                            value: s(b),
                        },
                    ],
                },
                5 => E::And {
                    args: vec![E::Under { scopes: vec![p(a)] }, E::True],
                },
                6 => E::Under { scopes: vec![p(a)] },
                7 => E::And {
                    args: vec![
                        E::Under { scopes: vec![d(b)] },
                        E::Not {
                            arg: Box::new(E::Under { scopes: vec![p(a)] }),
                        },
                    ],
                },
                _ => E::IdIn {
                    ids: vec![format!("r{}", rnd(600)).parse().unwrap()],
                },
            });
        }
        let condition = if rnd(3) == 0 {
            E::Not {
                arg: Box::new(E::Or { args }),
            }
        } else {
            E::Or { args }
        };
        let f = ListFilter {
            tenant: tenant(),
            type_name: "item".parse().unwrap(),
            rev: 1,
            ids_in: vec![],
            container_in: vec![d(0), d(1), d(2)],
            condition: Some(condition),
        };
        let mut rows = Vec::new();
        for compile in [sql::where_clause, sql::where_clause_plain] {
            let (clause, params) = compile(&f, &cols, 1).unwrap();
            if clause.contains("tutela_vals") {
                grouped_seen += 1;
            }
            let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                params.iter().map(sql::Param::as_sql).collect();
            let mut ids: Vec<String> = tx
                .query(&format!("SELECT id FROM eq_item WHERE {clause}"), &refs)
                .await
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            ids.sort();
            rows.push(ids);
        }
        assert_eq!(rows[0], rows[1], "filter {f:?}");
    }
    assert!(
        grouped_seen >= 40,
        "the grouped form came up {grouped_seen} times"
    );
    // A long scope list (over 64) uses the hashed form; it lists the same
    // rows as `&&`.
    let long: Vec<String> = (0..70)
        .map(|i| {
            if i % 2 == 0 {
                format!("project:p{}", i % 30)
            } else {
                format!("project:gone{i}")
            }
        })
        .collect();
    let mut by = Vec::new();
    for q in [
        "SELECT id FROM eq_item WHERE ancestors && $1 ORDER BY id",
        "SELECT id FROM eq_item WHERE EXISTS (SELECT 1 FROM unnest(ancestors) AS tutela_anc(tutela_scope) WHERE tutela_scope = ANY($1)) ORDER BY id",
    ] {
        let ids: Vec<String> = tx
            .query(q, &[&long])
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        by.push(ids);
    }
    assert_eq!(by[0], by[1]);
    assert!(!by[0].is_empty());
    let f = ListFilter {
        tenant: tenant(),
        type_name: "item".parse().unwrap(),
        rev: 1,
        ids_in: vec![],
        container_in: (0..70).map(|i| p(i % 30)).collect(),
        condition: None,
    };
    let (clause, _) = sql::where_clause(&f, &cols, 1).unwrap();
    assert!(clause.contains("tutela_scope = ANY("), "{clause}");
    // A product column may not take an alias the grouped form uses.
    let mut bad = columns();
    bad.fields
        .insert("status".parse().unwrap(), "tutela_vals".into());
    let e = sql::where_clause(
        &ListFilter {
            tenant: tenant(),
            type_name: "item".parse().unwrap(),
            rev: 1,
            ids_in: vec![],
            container_in: vec![],
            condition: Some(E::Eq {
                attr: "status".parse().unwrap(),
                value: V::Boolean(true),
            }),
        },
        &bad,
        1,
    )
    .unwrap_err();
    assert_eq!(e.kind(), SqlErrorKind::Column);
}
