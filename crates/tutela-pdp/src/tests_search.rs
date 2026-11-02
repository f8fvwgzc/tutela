//! The searches on small worlds: what a field condition hides, the bounds
//! of a page, and how a provider's failure ends a search. The property test
//! against `check` on random worlds is in `tests_props`.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use tutela_contracts::keys::{ActionKey, ResourceId};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::{OrgId, TenantKey};

use crate::model::{GroupKey, Model, RoleKey};
use crate::search::SubjectSearchRequest;
use crate::tests_check::{agent, user};
use crate::{
    Binding, Group, ListFilterRequest, MAX_SEARCH_SCAN, Member, PathEntry, Pdp, PdpError,
    ResourceRef, ScopePathError, ScopePathProblem, ScopePaths, Subject, TenantData,
};

const MANIFEST: &str = r#"
version = 1
[app]
name = "search"

[types.project]
parent = "org"
container = true

[types.doc]
parent = "project"
[types.doc.fields]
owner = { sensitivity = "internal", type = "principal", grants_access = true }

[roles.reader]
grants = { project = "read", doc = "read" }

[roles.mine]
grants = { project = "read", doc = "read" }

[[conditions]]
role = "mine"
type = "doc"
when = { is_principal = "owner" }
else = "none"
"#;

const OTHER_MANIFEST: &str = r#"
version = 1
[app]
name = "search"

[types.project]
parent = "org"
container = true

[types.doc]
parent = "project"

[roles.reader]
grants = { project = "read", doc = "read" }
"#;

fn tenant() -> TenantKey {
    TenantKey::new(
        "https://auth.example.test".parse().unwrap(),
        "ten_0193a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b".parse().unwrap(),
    )
}

fn org() -> OrgId {
    "org_0193a1b2-c3d4-7f00-9a00-000000000002".parse().unwrap()
}

fn entry(t: &str, id: &str) -> PathEntry {
    PathEntry::new(t.parse().unwrap(), ResourceId::parse(id).unwrap())
}

fn root() -> PathEntry {
    PathEntry::org(&org()).unwrap()
}

fn bind(n: u32, subject: Subject, role: &str, scope: PathEntry) -> Binding {
    Binding {
        id: format!("ra_0193a1b2-c3d4-7a00-8000-{n:012x}")
            .parse()
            .unwrap(),
        subject,
        role: RoleKey::parse(role).unwrap(),
        scope,
    }
}

fn who(p: &Principal) -> Subject {
    Subject::Principal(p.clone())
}

/// A provider that knows these scopes, and fails for `broken`.
#[derive(Default)]
struct Scopes {
    map: HashMap<PathEntry, Vec<PathEntry>>,
    broken: Option<PathEntry>,
    no_below: bool,
}

impl Scopes {
    fn add(&mut self, s: &PathEntry, path: &[PathEntry]) {
        self.map.insert(s.clone(), path.to_vec());
    }
}

impl ScopePaths for Scopes {
    fn ancestors(
        &self,
        _: &TenantKey,
        scope: &PathEntry,
    ) -> Result<Vec<PathEntry>, ScopePathError> {
        if self.broken.as_ref() == Some(scope) {
            return Err(ScopePathError::Unavailable);
        }
        self.map.get(scope).cloned().ok_or(ScopePathError::NotFound)
    }

    fn below(
        &self,
        _: &TenantKey,
        scopes: &[PathEntry],
    ) -> Option<Result<Vec<PathEntry>, ScopePathError>> {
        (!self.no_below).then(|| {
            Ok(self
                .map
                .iter()
                .filter(|(_, path)| path.iter().any(|a| scopes.contains(a)))
                .map(|(s, _)| s.clone())
                .collect())
        })
    }
}

fn pdp(manifest: &str, data: TenantData) -> Pdp {
    let mut pdp = Pdp::new();
    let model = Arc::new(Model::from_toml(manifest).unwrap());
    pdp.load(tenant(), 1, model, data).unwrap();
    pdp
}

fn list(p: &Principal) -> ListFilterRequest {
    ListFilterRequest {
        tenant: tenant(),
        subject: p.clone(),
        actors: Vec::new(),
        action: ActionKey::parse("doc:read").unwrap(),
        at_least_revision: None,
    }
}

fn data(bindings: Vec<Binding>) -> TenantData {
    TenantData {
        orgs: BTreeSet::from([org()]),
        bindings,
        ..TenantData::default()
    }
}

/// One project with `n` docs. `sub` is a project under it.
fn tree(n: usize) -> Scopes {
    let mut s = Scopes::default();
    let p = entry("project", "p");
    s.add(&p, &[root()]);
    for i in 0..n {
        s.add(&entry("doc", &format!("d-{i:05}")), &[p.clone(), root()]);
    }
    s
}

#[test]
fn a_resource_behind_a_field_condition_is_not_named_and_the_filter_still_covers_it() {
    let u = user(1);
    let pdp = pdp(
        MANIFEST,
        data(vec![bind(1, who(&u), "mine", entry("project", "p"))]),
    );
    let page = pdp.search_resources(&list(&u), &tree(3), None, 10).unwrap();
    assert!(page.results.is_empty(), "{:?}", page.results);
    assert!(page.next.is_none());
    assert_eq!(page.filter.container_in, [entry("project", "p")]);
    assert!(page.filter.condition.is_some());

    // With no field condition the same docs are all named.
    let pdp = crate::tests_search::pdp(
        MANIFEST,
        data(vec![bind(1, who(&u), "reader", entry("project", "p"))]),
    );
    let page = pdp.search_resources(&list(&u), &tree(3), None, 10).unwrap();
    assert_eq!(page.results.len(), 3);
}

#[test]
fn pages_cover_the_list_once_each_in_order() {
    let u = user(1);
    let pdp = pdp(
        MANIFEST,
        data(vec![bind(1, who(&u), "reader", entry("project", "p"))]),
    );
    let paths = tree(7);
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = pdp
            .search_resources(&list(&u), &paths, after.as_ref(), 3)
            .unwrap();
        assert!(page.results.len() <= 3);
        seen.extend(page.results);
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    let want: Vec<_> = (0..7).map(|i| entry("doc", &format!("d-{i:05}"))).collect();
    assert_eq!(seen, want);
}

/// A scope a principal may not read below costs scan budget and gives no
/// result. The page ends short, with a cursor, and the list goes on.
#[test]
fn a_long_scan_ends_a_page_short_and_never_ends_the_list() {
    let u = user(1);
    let p = entry("project", "p");
    let hidden = entry("project", "hidden");
    let mut data = data(vec![bind(1, who(&u), "reader", p.clone())]);
    data.private_scopes.insert(hidden.clone());
    let pdp = pdp(MANIFEST, data);

    let mut paths = Scopes::default();
    paths.add(&p, &[root()]);
    paths.add(&hidden, &[p.clone(), root()]);
    // Sorted first, and all denied.
    for i in 0..MAX_SEARCH_SCAN + 5 {
        paths.add(
            &entry("doc", &format!("a-{i:06}")),
            &[hidden.clone(), p.clone(), root()],
        );
    }
    let open = entry("doc", "z-last");
    paths.add(&open, &[p.clone(), root()]);

    let first = pdp.search_resources(&list(&u), &paths, None, 10).unwrap();
    assert!(first.results.is_empty());
    let next = first.next.expect("a cut page must have a cursor");
    let second = pdp
        .search_resources(&list(&u), &paths, Some(&next), 10)
        .unwrap();
    assert_eq!(second.results, [open]);
    assert!(second.next.is_none());
}

#[test]
fn a_provider_that_fails_ends_the_search_and_never_shortens_it() {
    let u = user(1);
    let pdp = pdp(
        MANIFEST,
        data(vec![bind(1, who(&u), "reader", entry("project", "p"))]),
    );
    let mut paths = tree(3);
    let broken = entry("doc", "d-00001");
    paths.broken = Some(broken.clone());
    let e = pdp
        .search_resources(&list(&u), &paths, None, 10)
        .unwrap_err();
    assert_eq!(
        e,
        PdpError::ScopePath {
            scope: broken,
            problem: ScopePathProblem::Unavailable
        }
    );

    let mut paths = tree(3);
    paths.no_below = true;
    assert!(matches!(
        pdp.search_resources(&list(&u), &paths, None, 10),
        Err(PdpError::InvalidInput { .. })
    ));
}

fn subject_search(kind: PrincipalKind, path: Vec<PathEntry>) -> SubjectSearchRequest {
    SubjectSearchRequest {
        tenant: tenant(),
        kind,
        action: ActionKey::parse("doc:read").unwrap(),
        resource: ResourceRef {
            type_name: "doc".parse().unwrap(),
            id: ResourceId::parse("d-1").unwrap(),
            path,
            attrs: crate::Attrs::new(),
        },
        at_least_revision: None,
    }
}

fn group(key: &str, members: Vec<Member>) -> Group {
    Group {
        key: GroupKey::parse(key).unwrap(),
        members,
    }
}

#[test]
fn a_subject_search_expands_groups_and_keeps_to_its_kind() {
    let p = entry("project", "p");
    let mut d = data(vec![
        bind(1, who(&user(1)), "reader", p.clone()),
        bind(
            2,
            Subject::Group(GroupKey::parse("team").unwrap()),
            "reader",
            p.clone(),
        ),
        bind(3, who(&agent(1)), "reader", p.clone()),
    ]);
    d.groups = vec![
        group(
            "team",
            vec![
                Member::Principal(user(2)),
                Member::Group(GroupKey::parse("inner").unwrap()),
            ],
        ),
        group("inner", vec![Member::Principal(user(3))]),
    ];
    let pdp = pdp(OTHER_MANIFEST, d);
    let page = pdp
        .search_subjects(
            &subject_search(PrincipalKind::User, vec![p.clone(), root()]),
            None,
            10,
        )
        .unwrap();
    assert_eq!(page.results, [user(1), user(2), user(3)]);
    assert!(page.next.is_none());
    let page = pdp
        .search_subjects(
            &subject_search(PrincipalKind::Agent, vec![p, root()]),
            None,
            10,
        )
        .unwrap();
    assert_eq!(page.results, [agent(1)]);
}

#[test]
fn a_subject_search_of_a_foreign_path_lists_no_one() {
    let p = entry("project", "p");
    let pdp = pdp(
        OTHER_MANIFEST,
        data(vec![bind(1, who(&user(1)), "reader", p.clone())]),
    );
    let foreign = entry("org", "org_0193a1b2-c3d4-7f00-9a00-0000000000ff");
    let page = pdp
        .search_subjects(
            &subject_search(PrincipalKind::User, vec![p, foreign]),
            None,
            10,
        )
        .unwrap();
    assert!(page.results.is_empty());
}

#[test]
fn a_subject_search_refuses_what_check_refuses() {
    let pdp = pdp(OTHER_MANIFEST, data(Vec::new()));
    let mut bad = subject_search(PrincipalKind::User, vec![root()]);
    bad.action = ActionKey::parse("doc:nothing").unwrap();
    assert!(matches!(
        pdp.search_subjects(&bad, None, 10),
        Err(PdpError::UnknownAction(_))
    ));
    let mut far = subject_search(PrincipalKind::User, vec![root()]);
    far.at_least_revision = Some(9);
    assert!(matches!(
        pdp.search_subjects(&far, None, 10),
        Err(PdpError::StaleBundle { .. })
    ));
}
