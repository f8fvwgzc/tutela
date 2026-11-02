//! Nobody grants what they do not hold (PERMISSION-MODEL.md 7.1 step 6,
//! ADR-0043).
//!
//! The property test makes a random change of a tenant's data, asks
//! `grant_excess` for a random granter, and, when it finds no excess, asks
//! `check` for every principal on every row: whatever anyone gained, the
//! granter held on that row before the change. So the check cannot pass a
//! change by reading the same code wrong twice: `check` knows the field
//! values, and the excess check does not.

use std::sync::Arc;

use proptest::prelude::*;
use tutela_contracts::decision::Decision;
use tutela_contracts::principal::Principal;

use crate::grant::grant_excess;
use crate::impact::MAX_IMPACT_WORK;
use crate::model::{GroupKey, Model};
use crate::testgen::{Node, Paths, Rng, Tenant, World, principals, world};
use crate::tests_check::{binding, direct, org_id, user};
use crate::tests_moves::with_more_bindings;
use crate::tests_props::check_req;
use crate::{Member, PathEntry, Pdp, PdpError, Subject, TenantData};

fn pdp(model: &Arc<Model>, t: &Tenant, data: TenantData, rev: u64) -> Option<Pdp> {
    let mut pdp = Pdp::new();
    pdp.load(t.key.clone(), rev, Arc::clone(model), data).ok()?;
    Some(pdp)
}

fn decide(pdp: &Pdp, t: &Tenant, p: &Principal, action: &str, row: &Node) -> Option<Decision> {
    match pdp.check(&check_req(t, p, &[], action, row)) {
        Ok(d) => Some(d),
        Err(PdpError::PathTooLong) => None,
        Err(e) => panic!("check failed: {e}"),
    }
}

/// One random change of `data`, the kind a binding route makes.
fn change(rng: &mut Rng, w: &World, t: &Tenant, data: &mut TenantData) {
    let mut roles: Vec<String> = w.spec.roles.iter().map(|r| r.key.clone()).collect();
    roles.extend(["member".to_owned(), "viewer".to_owned(), "owner".to_owned()]);
    let mut scopes: Vec<PathEntry> = t
        .nodes
        .iter()
        .filter(|n| n.path.len() <= crate::MAX_PATH)
        .map(|n| n.entry.clone())
        .collect();
    // The org, from the first node's path.
    scopes.push(t.nodes[0].path.last().cloned().unwrap());
    let groups: Vec<GroupKey> = data.groups.iter().map(|g| g.key.clone()).collect();
    // A group that conditions may name before it exists (testgen's "nope").
    let nope = GroupKey::parse("nope").unwrap();
    match rng.below(7) {
        6 if !groups.contains(&nope) => {
            data.groups.push(crate::Group {
                key: nope,
                members: Vec::new(),
            });
        }
        0 | 1 => {
            let subject = if !groups.is_empty() && rng.chance(30) {
                Subject::Group(rng.pick(&groups).clone())
            } else {
                direct(rng.pick(&principals()))
            };
            let s = rng.pick(&scopes).clone();
            if !data
                .bindings
                .iter()
                .any(|b| b.scope == s && b.subject == subject)
            {
                let role = rng.pick(&roles).clone();
                data.bindings.push(binding("ra_new", subject, &role, s));
            }
        }
        2 if !data.bindings.is_empty() => {
            let i = rng.below(data.bindings.len());
            data.bindings.remove(i);
        }
        3 if !data.groups.is_empty() => {
            let g = rng.below(data.groups.len());
            let p = Member::Principal(rng.pick(&principals()).clone());
            if !data.groups[g].members.contains(&p) {
                data.groups[g].members.push(p);
            }
        }
        4 if !data.groups.is_empty() => {
            let g = rng.below(data.groups.len());
            if !data.groups[g].members.is_empty() {
                let m = rng.below(data.groups[g].members.len());
                data.groups[g].members.remove(m);
            }
        }
        _ => {
            let s = rng.pick(&scopes).clone();
            if !s.is_org() && !data.private_scopes.remove(&s) {
                data.private_scopes.insert(s);
            }
        }
    }
}

#[derive(Default, Debug)]
struct Stats {
    checks: usize,
    passed: usize,
    excess: usize,
    /// Someone gained something on a row in a change that passed.
    gains_passed: usize,
}

/// The granter's answer covers every gain anyone made on `row`.
fn covers(
    (before, after): (&Pdp, &Pdp),
    t: &Tenant,
    granter: &Principal,
    row: &Node,
    all: &[String],
    seed: u64,
    stats: &mut Stats,
) {
    for p in principals() {
        for a in all {
            let (Some(d0), Some(d1)) =
                (decide(before, t, &p, a, row), decide(after, t, &p, a, row))
            else {
                continue;
            };
            let Some(g) = decide(before, t, granter, a, row) else {
                continue;
            };
            let ctx = || {
                format!(
                    "seed {seed}: {p} {a} on {} by {granter}: {d0:?} -> {d1:?}; granter {g:?}",
                    row.entry
                )
            };
            if d1.level > d0.level {
                stats.gains_passed += 1;
                assert!(g.level >= d1.level, "{}", ctx());
            }
            if d1.is_allowed() && !d0.is_allowed() {
                stats.gains_passed += 1;
                assert!(g.is_allowed(), "{}", ctx());
            }
            for f in d1.field_mask.read() {
                if !d0.field_mask.read().contains(f) {
                    stats.gains_passed += 1;
                    assert!(g.field_mask.read().contains(f), "{}", ctx());
                }
            }
        }
    }
}

fn nobody_gets_more_than_the_granter(seed: u64, stats: &mut Stats) {
    let mut w = world(seed);
    let mut rng = Rng::new(seed ^ 0x6772_616e);
    with_more_bindings(&mut rng, &mut w);
    let paths = Paths::of(&w.tenants);
    let all = w.spec.actions();
    let granters: Vec<Principal> = principals()
        .into_iter()
        .filter(|p| p.kind() != tutela_contracts::principal::PrincipalKind::Agent)
        .collect();
    for t in &w.tenants {
        let mut data = t.data.clone();
        change(&mut rng, &w, t, &mut data);
        let (Some(before), Some(after)) = (
            pdp(&w.model, t, t.data.clone(), 7),
            pdp(&w.model, t, data, 8),
        ) else {
            continue;
        };
        let granter = rng.pick(&granters).clone();
        let r = grant_excess(&before, &after, &t.key, &paths, &granter, MAX_IMPACT_WORK).unwrap();
        assert!(r.complete, "seed {seed}");
        stats.checks += 1;
        // Reading it again gives the same answer.
        assert_eq!(
            r,
            grant_excess(&before, &after, &t.key, &paths, &granter, MAX_IMPACT_WORK).unwrap()
        );
        if !r.lines.is_empty() {
            stats.excess += 1;
            continue;
        }
        stats.passed += 1;
        for row in t.rows() {
            covers((&before, &after), t, &granter, row, &all, seed, stats);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn tm08_a_change_that_passes_gives_nobody_more_than_the_granter(seed in any::<u64>()) {
        nobody_gets_more_than_the_granter(seed, &mut Stats::default());
    }

    /// A check that stops early never reads as "no excess".
    #[test]
    fn a_grant_check_that_stops_early_never_passes(seed in any::<u64>(), limit in 0usize..60) {
        let mut w = world(seed);
        let mut rng = Rng::new(seed);
        with_more_bindings(&mut rng, &mut w);
        let paths = Paths::of(&w.tenants);
        for t in &w.tenants {
            let mut data = t.data.clone();
            change(&mut rng, &w, t, &mut data);
            let (Some(before), Some(after)) = (pdp(&w.model, t, t.data.clone(), 7), pdp(&w.model, t, data, 8)) else {
                continue;
            };
            let full = grant_excess(&before, &after, &t.key, &paths, &user(3), MAX_IMPACT_WORK).unwrap();
            let cut = grant_excess(&before, &after, &t.key, &paths, &user(3), limit).unwrap();
            if cut.complete {
                prop_assert_eq!(&cut, &full);
            } else {
                prop_assert!(!cut.no_impact());
            }
        }
    }
}

/// The property test above is not empty: changes pass, changes are refused,
/// and the changes that pass give someone something.
#[test]
fn tm08_the_grant_test_compares_enough() {
    let mut s = Stats::default();
    for seed in 1..=150 {
        nobody_gets_more_than_the_granter(seed, &mut s);
    }
    assert!(s.checks > 200, "{s:?}");
    assert!(s.passed > 50, "{s:?}");
    assert!(s.excess > 30, "{s:?}");
    assert!(s.gains_passed > 50, "{s:?}");
}

const MODEL: &str = r#"
version = 1
[app]
name = "grants"

[types.project]
parent = "org"
container = true

[types.contract]
parent = "project"

[types.contract.fields]
title = { sensitivity = "internal" }
budget = { sensitivity = "internal" }
status = { sensitivity = "internal", grants_access = true }

[roles.reader]
grants = { project = "read", contract = "read" }

[roles.editor]
grants = { project = "write", contract = "write" }

[roles.assignee_editor]
grants = { project = "write", contract = "write" }

[[conditions]]
role = "assignee_editor"
type = "contract"
when = { eq = { field = "status", value = "open" } }
else = "read"
"#;

#[test]
fn an_owner_grants_and_a_reader_does_not() {
    use crate::tests_check::{entry, tenant};
    let org = PathEntry::org(&org_id(1)).unwrap();
    let p1 = entry("project", "p1");
    let (owner, reader, newcomer) = (user(1), user(2), user(3));
    let data = TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_1", direct(&owner), "owner", p1.clone()),
            binding("ra_2", direct(&reader), "reader", p1.clone()),
        ],
        groups: vec![crate::Group {
            key: GroupKey::parse("everyone").unwrap(),
            members: vec![Member::Principal(reader.clone())],
        }],
        ..TenantData::default()
    };
    let model = Arc::new(Model::from_toml(MODEL).unwrap());
    let load = |d: TenantData, rev| {
        let mut pdp = Pdp::new();
        pdp.load(tenant(1), rev, Arc::clone(&model), d).unwrap();
        pdp
    };
    let paths = Paths {
        map: [((tenant(1), p1.clone()), vec![org.clone()])]
            .into_iter()
            .collect(),
        ..Paths::default()
    };
    let before = load(data.clone(), 1);
    let with = |b: crate::Binding| {
        let mut d = data.clone();
        d.bindings.push(b);
        load(d, 2)
    };
    // The owner may make a newcomer an editor of the project.
    let editor = with(binding("ra_3", direct(&newcomer), "editor", p1.clone()));
    let r = grant_excess(
        &before,
        &editor,
        &tenant(1),
        &paths,
        &owner,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(r.no_impact(), "{r:?}");
    // A reader may not: the newcomer would write, and the reader cannot.
    let r = grant_excess(
        &before,
        &editor,
        &tenant(1),
        &paths,
        &reader,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(!r.no_impact());
    assert!(
        r.summary()
            .iter()
            .any(|l| l.starts_with("1 user gains write on contract")),
        "{:?}",
        r.summary()
    );
    // A reader may give what it holds itself.
    let same = with(binding("ra_3", direct(&newcomer), "reader", p1.clone()));
    let r = grant_excess(&before, &same, &tenant(1), &paths, &reader, MAX_IMPACT_WORK).unwrap();
    assert!(r.no_impact(), "{r:?}");
    // Nobody may make someone else an owner unless it is one.
    let owner2 = with(binding("ra_3", direct(&newcomer), "owner", p1.clone()));
    let r = grant_excess(
        &before,
        &owner2,
        &tenant(1),
        &paths,
        &reader,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(
        r.lines.iter().any(|l| l.key == "project:manage_access"),
        "{r:?}"
    );
    // A group's role reaches its members. The reader in the group gains
    // editor at the org, but not at p1, where its own assignment wins.
    let group = with(binding(
        "ra_3",
        Subject::Group(GroupKey::parse("everyone").unwrap()),
        "editor",
        org.clone(),
    ));
    let r = grant_excess(&before, &group, &tenant(1), &paths, &owner, MAX_IMPACT_WORK).unwrap();
    assert!(
        !r.no_impact(),
        "the owner of p1 holds nothing at the org: {r:?}"
    );
    assert!(
        r.lines.iter().all(|l| l.scopes == vec![org.clone()]),
        "{r:?}"
    );
    // Removing an assignment can widen: the reader's own assignment hides
    // nothing here, but taking the owner's away from the owner gives nothing,
    // and taking it as the reader is a loss only.
    let mut gone = data.clone();
    gone.bindings.retain(|b| b.id.as_str() != "ra_1");
    let r = grant_excess(
        &before,
        &load(gone, 2),
        &tenant(1),
        &paths,
        &reader,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(r.no_impact(), "a loss is never an excess: {r:?}");
}

/// A grant at a scope reaches the places below it: there the granter may
/// hold less than at the scope (its own narrower assignment), and the gain
/// is held up to that.
#[test]
fn a_grant_is_held_up_to_the_granter_below_the_scope_too() {
    use crate::tests_check::{entry, tenant};
    let org = PathEntry::org(&org_id(1)).unwrap();
    let p1 = entry("project", "p1");
    let (granter, newcomer) = (user(1), user(3));
    let data = TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_1", direct(&granter), "editor", org.clone()),
            binding("ra_2", direct(&granter), "reader", p1.clone()),
        ],
        ..TenantData::default()
    };
    let model = Arc::new(Model::from_toml(MODEL).unwrap());
    let load = |d: TenantData, rev| {
        let mut pdp = Pdp::new();
        pdp.load(tenant(1), rev, Arc::clone(&model), d).unwrap();
        pdp
    };
    let paths = Paths {
        map: [((tenant(1), p1.clone()), vec![org.clone()])]
            .into_iter()
            .collect(),
        ..Paths::default()
    };
    let mut after = data.clone();
    after
        .bindings
        .push(binding("ra_3", direct(&newcomer), "editor", org.clone()));
    let r = grant_excess(
        &load(data, 1),
        &load(after, 2),
        &tenant(1),
        &paths,
        &granter,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(!r.no_impact(), "{r:?}");
    assert!(
        r.lines.iter().all(|l| l.scopes == vec![p1.clone()]),
        "{r:?}"
    );
}

/// The granter is taken at the lowest its conditions can leave it: a role
/// that writes only open contracts does not give a role that writes all.
#[test]
fn a_granter_with_a_condition_is_held_at_its_lowest() {
    use crate::tests_check::{entry, tenant};
    let org = PathEntry::org(&org_id(1)).unwrap();
    let p1 = entry("project", "p1");
    let (granter, newcomer) = (user(1), user(3));
    let data = TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![binding(
            "ra_1",
            direct(&granter),
            "assignee_editor",
            p1.clone(),
        )],
        ..TenantData::default()
    };
    let model = Arc::new(Model::from_toml(MODEL).unwrap());
    let load = |d: TenantData, rev| {
        let mut pdp = Pdp::new();
        pdp.load(tenant(1), rev, Arc::clone(&model), d).unwrap();
        pdp
    };
    let paths = Paths {
        map: [((tenant(1), p1.clone()), vec![org.clone()])]
            .into_iter()
            .collect(),
        ..Paths::default()
    };
    let before = load(data.clone(), 1);
    let mut after = data.clone();
    after
        .bindings
        .push(binding("ra_2", direct(&newcomer), "editor", p1.clone()));
    let r = grant_excess(
        &before,
        &load(after, 2),
        &tenant(1),
        &paths,
        &granter,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(
        r.lines
            .iter()
            .any(|l| l.key == "contract" && l.to == "write"),
        "{r:?}"
    );
    // Not even its own role: the rule does not pair the granter's conditions
    // with the grantee's, so it takes the granter at its lowest (ADR-0043
    // item 3, a known limit that errs on the side of refusing).
    let mut same = data;
    same.bindings
        .push(binding("ra_2", direct(&newcomer), "assignee_editor", p1));
    let r = grant_excess(
        &before,
        &load(same, 2),
        &tenant(1),
        &paths,
        &granter,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(
        r.lines.iter().any(|l| l.key == "contract" && l.conditional),
        "{r:?}"
    );
}

/// A role whose condition reads group membership: `in_group` and its
/// negation, on a group that exists and on one that does not yet.
const GROUP_MODEL: &str = r#"
version = 1
[app]
name = "grants"

[types.project]
parent = "org"
container = true

[types.contract]
parent = "project"

[types.contract.fields]
title = { sensitivity = "internal" }

[roles.reader]
grants = { project = "read", contract = "read" }

[roles.editor_in_group]
grants = { project = "write", contract = "write" }

[roles.editor_outside]
grants = { project = "write", contract = "write" }

[[conditions]]
role = "editor_in_group"
type = "contract"
when = { in_group = "editors" }
else = "read"

[[conditions]]
role = "editor_outside"
type = "contract"
when = { not = { in_group = "outsiders" } }
else = "read"
"#;

/// A change of group membership, or a new group, can make a condition that
/// reads groups hold where it failed: the member gains with no assignment
/// changed. The granter must hold that gain. Found by the property test
/// (seed 5412397625890240684): before, `grant_excess` paired the condition
/// across the two sides and saw no gain.
#[test]
fn tm08_a_group_change_that_makes_a_condition_hold_is_a_grant() {
    use crate::tests_check::{entry, tenant};
    let org = PathEntry::org(&org_id(1)).unwrap();
    let p1 = entry("project", "p1");
    let (granter, member, other) = (user(1), user(2), user(3));
    let group = |key: &str, members: &[&Principal]| crate::Group {
        key: GroupKey::parse(key).unwrap(),
        members: members
            .iter()
            .map(|p| Member::Principal((*p).clone()))
            .collect(),
    };
    let data = TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_1", direct(&granter), "reader", p1.clone()),
            binding("ra_2", direct(&member), "editor_in_group", p1.clone()),
            binding("ra_3", direct(&other), "editor_outside", p1.clone()),
        ],
        groups: vec![group("editors", &[]), group("sales", &[])],
        ..TenantData::default()
    };
    let model = Arc::new(Model::from_toml(GROUP_MODEL).unwrap());
    let load = |d: TenantData, rev| {
        let mut pdp = Pdp::new();
        pdp.load(tenant(1), rev, Arc::clone(&model), d).unwrap();
        pdp
    };
    let paths = Paths {
        map: [((tenant(1), p1.clone()), vec![org.clone()])]
            .into_iter()
            .collect(),
        ..Paths::default()
    };
    let before = load(data.clone(), 1);
    let excess = |after: TenantData| {
        grant_excess(
            &before,
            &load(after, 2),
            &tenant(1),
            &paths,
            &granter,
            MAX_IMPACT_WORK,
        )
        .unwrap()
    };

    // The member joins `editors`: its condition now holds, and it writes
    // contracts at p1, which the reader does not.
    let mut joined = data.clone();
    joined.groups[0]
        .members
        .push(Member::Principal(member.clone()));
    let r = excess(joined);
    assert!(
        r.lines
            .iter()
            .any(|l| l.key == "contract" && l.to == "write" && l.scopes == vec![p1.clone()]),
        "{r:?}"
    );

    // A new group named by a negated condition: before, the condition named
    // a group that did not exist and failed for everyone (MANIFEST.md 8);
    // now it holds for whoever is not in the group.
    let mut made = data.clone();
    made.groups.push(group("outsiders", &[]));
    let r = excess(made);
    assert!(
        r.lines
            .iter()
            .any(|l| l.key == "contract" && l.to == "write"),
        "{r:?}"
    );

    // Joining a group no condition reads changes nothing for anyone.
    let mut sales = data.clone();
    sales.groups[1]
        .members
        .push(Member::Principal(member.clone()));
    assert!(excess(sales).no_impact());

    // A granter who holds the gain may make it.
    let mut owner_data = data.clone();
    owner_data.bindings[0] = binding("ra_1", direct(&granter), "owner", p1.clone());
    let before_owner = load(owner_data.clone(), 1);
    let mut joined = owner_data;
    joined.groups[0].members.push(Member::Principal(member));
    let r = grant_excess(
        &before_owner,
        &load(joined, 2),
        &tenant(1),
        &paths,
        &granter,
        MAX_IMPACT_WORK,
    )
    .unwrap();
    assert!(r.no_impact(), "{r:?}");
}
