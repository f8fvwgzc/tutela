//! `list_filter` on the worked example (PERMISSION-MODEL.md 17.3), its
//! JSON form, the scope-path provider rules of ADR-0011 F1, and the limits
//! of CONTRACTS.md 6.6.

use std::cell::Cell;

use tutela_contracts::decision::Effect;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;

use crate::testgen::Node;
use crate::testgen::row_matches;
use crate::tests_check::{
    CLAUSE, JAE, OMAR, action, agent, binding, direct, entry, kestrel, kestrel_data, org, org_id,
    path_of, pdp_with, proc, rid, sup, tenant, user,
};
use crate::{
    AttrValue, Attrs, CheckRequest, FilterExpr, ListFilter, ListFilterRequest, MAX_IDS_IN,
    PathEntry, Pdp, PdpError, ScopePathError, ScopePathProblem, ScopePaths,
};

/// The worked example's tree, for tenant 1 only.
struct Kestrel {
    calls: Cell<usize>,
}

impl Kestrel {
    fn new() -> Self {
        Self {
            calls: Cell::new(0),
        }
    }
}

impl ScopePaths for Kestrel {
    fn ancestors(
        &self,
        t: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        self.calls.set(self.calls.get() + 1);
        if *t != tenant(1) {
            return Err(ScopePathError::NotFound);
        }
        match scope.type_name.as_str() {
            "department" | "matter" => Ok(path_of(scope)),
            "contract" if ["c-204", "c-207", "c-219", "c-311"].contains(&scope.id.as_str()) => {
                Ok(path_of(scope))
            }
            "contract" => Ok(vec![sup(), proc(), org()]),
            _ => Err(ScopePathError::NotFound),
        }
    }
}

/// A provider that answers with a fixed path, or an error.
struct Fixed(Result<Vec<PathEntry>, ScopePathError>);

impl ScopePaths for Fixed {
    fn ancestors(&self, _: &TenantKey, _: &PathEntry) -> Result<Vec<PathEntry>, ScopePathError> {
        self.0.clone()
    }
}

fn contracts() -> Vec<Node> {
    ["c-204", "c-207", "c-219", "c-311"]
        .into_iter()
        .map(|id| {
            let e = entry("contract", id);
            let mut attrs = Attrs::new();
            if id == "c-204" {
                attrs.insert(
                    "assignee".parse().unwrap(),
                    AttrValue::String(agent(CLAUSE).to_string()),
                );
            }
            Node {
                path: path_of(&e),
                entry: e,
                attrs,
            }
        })
        .collect()
}

fn list(
    pdp: &Pdp,
    p: &Principal,
    actors: Vec<Principal>,
    act: &str,
) -> Result<ListFilter, PdpError> {
    pdp.list_filter(
        &ListFilterRequest {
            tenant: tenant(1),
            subject: p.clone(),
            actors,
            action: action(act),
            at_least_revision: None,
        },
        &Kestrel::new(),
    )
}

fn rows(f: &ListFilter) -> Vec<String> {
    contracts()
        .iter()
        .filter(|r| row_matches(f, r))
        .map(|r| r.entry.id.to_string())
        .collect()
}

/// The filter agrees with `check` on every contract of the example.
fn agrees(pdp: &Pdp, p: &Principal, actors: &[Principal], act: &str, f: &ListFilter) {
    for r in contracts() {
        let d = pdp
            .check(&CheckRequest {
                tenant: tenant(1),
                subject: p.clone(),
                actors: actors.to_vec(),
                action: action(act),
                resource: r.resource(),
                fields: None,
                at_least_revision: None,
            })
            .unwrap();
        assert_eq!(
            d.effect == Effect::Allow,
            row_matches(f, &r),
            "{act} {}",
            r.entry
        );
    }
}

#[test]
fn jae_lists_the_contracts_he_may_read() {
    let pdp = kestrel();
    let f = list(&pdp, &user(JAE), vec![], "contract:read").unwrap();
    assert_eq!(rows(&f), ["c-204", "c-207", "c-219"]);
    assert_eq!(f.container_in, [proc(), sup()]);
    assert!(f.ids_in.is_empty());
    assert_eq!(f.rev, 42);
    agrees(&pdp, &user(JAE), &[], "contract:read", &f);
    // For writes, Viewer on the matter is too low.
    let f = list(&pdp, &user(JAE), vec![], "contract:write").unwrap();
    assert_eq!(rows(&f), ["c-219"]);
    assert_eq!(f.container_in, [proc()]);
    agrees(&pdp, &user(JAE), &[], "contract:write", &f);
}

#[test]
fn tm03_delegated_lists_are_the_overlap() {
    let pdp = kestrel();
    let actors = vec![agent(CLAUSE)];
    let f = list(&pdp, &user(JAE), actors.clone(), "contract:read").unwrap();
    assert_eq!(rows(&f), ["c-204", "c-207"]);
    agrees(&pdp, &user(JAE), &actors, "contract:read", &f);
    // Clause may write only what it is assigned.
    let f = list(&pdp, &user(OMAR), actors.clone(), "contract:write").unwrap();
    assert_eq!(rows(&f), ["c-204"]);
    agrees(&pdp, &user(OMAR), &actors, "contract:write", &f);
    // Owner-only actions never pass delegation: no rows, no provider call.
    let k = Kestrel::new();
    let req = ListFilterRequest {
        tenant: tenant(1),
        subject: user(OMAR),
        actors,
        action: action("contract:manage_access"),
        at_least_revision: None,
    };
    let f = pdp.list_filter(&req, &k).unwrap();
    assert!(f.matches_nothing());
    assert_eq!(k.calls.get(), 0);
}

#[test]
fn the_org_owner_lists_everything_in_the_org() {
    let pdp = kestrel();
    let f = list(
        &pdp,
        &user(crate::tests_check::DANA),
        vec![],
        "contract:delete",
    )
    .unwrap();
    assert_eq!(rows(&f), ["c-204", "c-207", "c-219", "c-311"]);
    assert_eq!(f.container_in, [org()]);
    assert_eq!(f.condition, None);
}

#[test]
fn nobody_with_no_assignment_lists_nothing_and_asks_nothing() {
    let pdp = kestrel();
    let k = Kestrel::new();
    let req = ListFilterRequest {
        tenant: tenant(1),
        subject: user(0x999),
        actors: vec![],
        action: action("contract:read"),
        at_least_revision: None,
    };
    let f = pdp.list_filter(&req, &k).unwrap();
    assert!(f.matches_nothing());
    assert_eq!(f.ids_in.len() + f.container_in.len(), 0);
    assert_eq!(k.calls.get(), 0);
}

#[test]
fn the_json_form_follows_the_contract() {
    let pdp = kestrel();
    let f = list(&pdp, &user(JAE), vec![], "contract:read").unwrap();
    let v: serde_json::Value = serde_json::to_value(&f).unwrap();
    assert_eq!(v["type"], "contract");
    assert_eq!(v["rev"], 42);
    assert_eq!(v["ids_in"], serde_json::json!([]));
    assert_eq!(
        v["container_in"],
        serde_json::json!([
            { "type": "department", "id": "d-procurement" },
            { "type": "matter", "id": "m-supplier-renewals" }
        ])
    );
    assert_eq!(v["condition"]["op"], "or");
    let text = serde_json::to_string(&v["condition"]).unwrap();
    assert!(text.contains(r#""op":"not""#), "{text}");
    assert!(text.contains(r#""op":"under""#), "{text}");
    assert!(text.contains(r#""id":"m-board-pricing""#), "{text}");
    // A filter with no condition leaves the key out.
    let all = list(
        &pdp,
        &user(crate::tests_check::DANA),
        vec![],
        "contract:read",
    )
    .unwrap();
    let v = serde_json::to_value(&all).unwrap();
    assert!(v.get("condition").is_none());
    // Leaves as the contract spells them.
    let leaf = FilterExpr::Eq {
        attr: "assignee".parse().unwrap(),
        value: crate::FilterValue::String("user:usr_x".into()),
    };
    assert_eq!(
        serde_json::to_value(&leaf).unwrap(),
        serde_json::json!({ "op": "eq", "attr": "assignee", "value": "user:usr_x" })
    );
    assert_eq!(
        serde_json::to_value(FilterExpr::True).unwrap(),
        serde_json::json!({ "op": "true" })
    );
}

fn with_jae(paths: &dyn ScopePaths) -> Result<ListFilter, PdpError> {
    kestrel().list_filter(
        &ListFilterRequest {
            tenant: tenant(1),
            subject: user(JAE),
            actors: vec![],
            action: action("contract:read"),
            at_least_revision: None,
        },
        paths,
    )
}

fn problem(r: Result<ListFilter, PdpError>) -> ScopePathProblem {
    match r {
        Err(PdpError::ScopePath { problem, .. }) => problem,
        other => panic!("expected a scope-path error, got {other:?}"),
    }
}

#[test]
fn tm10_a_provider_miss_fails_the_whole_list() {
    assert_eq!(
        problem(with_jae(&Fixed(Err(ScopePathError::NotFound)))),
        ScopePathProblem::NotFound
    );
    assert_eq!(
        problem(with_jae(&Fixed(Err(ScopePathError::Unavailable)))),
        ScopePathProblem::Unavailable
    );
}

#[test]
fn tm10_a_path_that_breaks_a_rule_fails_the_whole_list() {
    let other_org = PathEntry::org(&org_id(2)).unwrap();
    assert_eq!(
        problem(with_jae(&Fixed(Ok(vec![proc(), other_org])))),
        ScopePathProblem::WrongTenant
    );
    assert_eq!(
        problem(with_jae(&Fixed(Ok(vec![])))),
        ScopePathProblem::Malformed
    );
    assert_eq!(
        problem(with_jae(&Fixed(Ok(vec![proc()])))),
        ScopePathProblem::Malformed
    );
    assert_eq!(
        problem(with_jae(&Fixed(Ok(vec![org(), proc(), org()])))),
        ScopePathProblem::Malformed
    );
    let long: Vec<PathEntry> = (0..32)
        .map(|i| entry("matter", &format!("m{i}")))
        .chain([org()])
        .collect();
    assert_eq!(
        problem(with_jae(&Fixed(Ok(long)))),
        ScopePathProblem::TooLong
    );
}

/// A provider that ignores the tenant, as a buggy one might: with ids that
/// are the same across tenants, it answers with the other tenant's path.
struct IgnoresTenant;

impl ScopePaths for IgnoresTenant {
    fn ancestors(
        &self,
        _: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        let other = PathEntry::org(&org_id(2)).unwrap();
        let mut p = path_of(scope);
        if let Some(last) = p.last_mut() {
            *last = other;
        }
        Ok(p)
    }
}

#[test]
fn tm10_a_path_from_another_tenant_is_refused() {
    assert_eq!(
        problem(with_jae(&IgnoresTenant)),
        ScopePathProblem::WrongTenant
    );
}

#[test]
fn tm10_a_filter_above_the_limits_fails_closed() {
    let mut data = kestrel_data();
    let u = user(0x500);
    for i in 0..=MAX_IDS_IN {
        data.bindings.push(binding(
            &format!("ra_many_{i}"),
            direct(&u),
            "viewer",
            entry("contract", &format!("c{i}")),
        ));
    }
    let pdp = pdp_with(data);
    assert_eq!(
        list(&pdp, &u, vec![], "contract:read"),
        Err(PdpError::FilterTooLarge("ids_in"))
    );
}

#[test]
fn an_assignment_on_the_row_itself_goes_into_ids_in() {
    let mut data = kestrel_data();
    let guest = user(0x600);
    data.bindings.push(binding(
        "ra_guest",
        direct(&guest),
        "guest",
        entry("contract", "c-219"),
    ));
    let pdp = pdp_with(data);
    let f = list(&pdp, &guest, vec![], "contract:read").unwrap();
    assert_eq!(f.ids_in, [rid("c-219")]);
    assert_eq!(rows(&f), ["c-219"]);
    agrees(&pdp, &guest, &[], "contract:read", &f);
    // Contracts are containers, so the scope is in `container_in` too.
    assert_eq!(f.container_in, [entry("contract", "c-219")]);
}

#[test]
fn private_scopes_are_asked_for_once_each() {
    let pdp = kestrel();
    let k = Kestrel::new();
    let req = ListFilterRequest {
        tenant: tenant(1),
        subject: user(JAE),
        actors: vec![],
        action: action("contract:read"),
        at_least_revision: None,
    };
    pdp.list_filter(&req, &k).unwrap();
    // proc (org-level department), sup (assigned and private), board
    // (private): three scopes, three calls.
    assert_eq!(k.calls.get(), 3);
}

#[test]
fn the_size_counts_nodes_depth_and_entries() {
    let e = FilterExpr::or(vec![
        FilterExpr::IdIn {
            ids: vec![rid("a"), rid("b")],
        },
        FilterExpr::not(FilterExpr::Under {
            scopes: vec![org(), proc(), sup()],
        }),
    ]);
    let s = e.size();
    assert_eq!((s.nodes, s.depth, s.entries), (4, 3, 5));
    // Folding keeps the AST small: true and false drop out, nests flatten.
    assert_eq!(FilterExpr::and(vec![FilterExpr::True, e.clone()]), e);
    assert_eq!(
        FilterExpr::or(vec![FilterExpr::True, e.clone()]),
        FilterExpr::True
    );
    assert_eq!(FilterExpr::not(FilterExpr::not(e.clone())), e);
}

/// A valid manifest can still give a filter above the limits of
/// CONTRACTS.md 6.6 (ADR-0012 asked ROADMAP item 4 to measure this). Here:
/// one role with 200 conditions (3 nodes each once nested `and`s are
/// flattened) on the listed type, and one principal with that role at 8
/// nested scopes. Each nesting level repeats the role's conditions, so the
/// filter has about 8 × 600 nodes. The list fails closed; `check` still
/// answers.
#[test]
fn tm10_a_valid_manifest_can_pass_the_limits_and_the_list_fails_closed() {
    use std::fmt::Write as _;
    use std::sync::Arc;

    use crate::model::Model;

    let mut toml = String::from(
        "version = 1\n[app]\nname = \"big\"\n\
         [types.proj]\nparent = [\"org\", \"proj\"]\ncontainer = true\n\
         [types.item]\nparent = \"proj\"\n\
         [types.item.fields]\n\
         status = { sensitivity = \"internal\", grants_access = true }\n\
         prio = { sensitivity = \"internal\", type = \"integer\", grants_access = true }\n\
         [roles.r]\ngrants = { proj = \"read\", item = \"write\" }\n",
    );
    for i in 0..200 {
        let _ = write!(
            toml,
            "[[conditions]]\nrole = \"r\"\ntype = \"item\"\nwhen = {{ and = [{{ eq = {{ field = \"status\", value = \"s{i}\" }} }}, {{ not = {{ eq = {{ field = \"prio\", value = {i} }} }} }}] }}\nelse = \"read\"\n"
        );
    }
    let model = Arc::new(Model::from_toml(&toml).unwrap());
    let u = user(0x700);
    let org_e = org();
    let projs: Vec<PathEntry> = (0..8).map(|i| entry("proj", &format!("p{i}"))).collect();
    let path_of_proj = |i: usize| -> Vec<PathEntry> {
        projs[..i]
            .iter()
            .rev()
            .cloned()
            .chain([org_e.clone()])
            .collect()
    };
    struct Chain(Vec<(PathEntry, Vec<PathEntry>)>);
    impl ScopePaths for Chain {
        fn ancestors(
            &self,
            _: &TenantKey,
            s: &PathEntry,
        ) -> Result<Vec<PathEntry>, ScopePathError> {
            self.0
                .iter()
                .find(|(e, _)| e == s)
                .map(|(_, p)| p.clone())
                .ok_or(ScopePathError::NotFound)
        }
    }
    let chain = Chain(
        (0..8)
            .map(|i| (projs[i].clone(), path_of_proj(i)))
            .collect(),
    );
    let load = |levels: usize| {
        let data = crate::TenantData {
            orgs: [org_id(1)].into(),
            bindings: (0..levels)
                .map(|i| binding(&format!("ra_{i}"), direct(&u), "r", projs[i].clone()))
                .collect(),
            ..crate::TenantData::default()
        };
        let mut pdp = Pdp::new();
        pdp.load(tenant(1), 1, Arc::clone(&model), data).unwrap();
        pdp
    };
    let req = ListFilterRequest {
        tenant: tenant(1),
        subject: u.clone(),
        actors: vec![],
        action: action("item:write"),
        at_least_revision: None,
    };
    // One level: about 600 nodes, under the limit.
    let one = load(1).list_filter(&req, &chain).unwrap();
    let size = one.size();
    assert!(
        size.nodes > 600 && size.nodes < crate::MAX_FILTER_NODES,
        "{size:?}"
    );
    // Eight levels: above the limit. The list fails closed.
    let eight = load(8);
    assert_eq!(
        eight.list_filter(&req, &chain),
        Err(PdpError::FilterTooLarge("condition nodes"))
    );
    // `check` on one item still answers.
    let mut attrs = Attrs::new();
    attrs.insert("status".parse().unwrap(), AttrValue::String("s0".into()));
    let d = eight
        .check(&CheckRequest {
            tenant: tenant(1),
            subject: u,
            actors: vec![],
            action: action("item:write"),
            resource: crate::ResourceRef {
                type_name: "item".parse().unwrap(),
                id: rid("i1"),
                path: [projs[7].clone()]
                    .into_iter()
                    .chain(path_of_proj(7))
                    .collect(),
                attrs,
            },
            fields: None,
            at_least_revision: None,
        })
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "condition_failed");
}
