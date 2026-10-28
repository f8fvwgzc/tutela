//! The property tests of the library gate (SECURITY.md, ROADMAP Phase A):
//! `list_filter` ≡ `check` (the differential test), no cross-tenant grant,
//! delegation ≤ person AND agent, and no widening.
//!
//! Each case is one random world (testgen): a model, two tenants whose
//! resource ids are the same strings, groups, private scopes inside private
//! scopes, field rules, conditions with `not` over often-null fields, gone
//! roles and roles given to the wrong kind of subject.

use std::collections::BTreeSet;
use std::sync::Arc;

use proptest::prelude::*;
use tutela_contracts::decision::{Decision, Effect, ReasonCode};
use tutela_contracts::keys::ActionKey;
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;

use crate::model::{Model, diff};
use crate::testgen::{
    ACTIONS, Node, Paths, Rng, Tenant, World, has_not_over_comparison, principals, row_matches,
    world,
};
use crate::tests_check::{agent, user};
use crate::{CheckRequest, ListFilterRequest, Pdp};

fn pdp_of(model: &Arc<Model>, tenants: &[&Tenant]) -> Pdp {
    let mut pdp = Pdp::new();
    for t in tenants {
        pdp.load(t.key.clone(), 7, Arc::clone(model), t.data.clone())
            .unwrap();
    }
    pdp
}

/// Who asks: every principal alone, every user with every agent, and one
/// chain of two agents.
fn askers() -> Vec<(Principal, Vec<Principal>)> {
    let mut out: Vec<(Principal, Vec<Principal>)> =
        principals().into_iter().map(|p| (p, vec![])).collect();
    for u in [user(1), user(2), user(3)] {
        for a in [agent(1), agent(2)] {
            out.push((u.clone(), vec![a]));
        }
    }
    out.push((user(4), vec![agent(1), agent(2)]));
    out
}

fn check_req(
    t: &Tenant,
    p: &Principal,
    actors: &[Principal],
    action: &str,
    row: &Node,
) -> CheckRequest {
    CheckRequest {
        tenant: t.key.clone(),
        subject: p.clone(),
        actors: actors.to_vec(),
        action: ActionKey::parse(action).unwrap(),
        resource: row.resource(),
        fields: None,
        at_least_revision: None,
    }
}

fn list_req(t: &Tenant, p: &Principal, actors: &[Principal], action: &str) -> ListFilterRequest {
    ListFilterRequest {
        tenant: t.key.clone(),
        subject: p.clone(),
        actors: actors.to_vec(),
        action: ActionKey::parse(action).unwrap(),
        at_least_revision: None,
    }
}

fn owner_only(action: &str) -> bool {
    matches!(
        action,
        "doc:seal" | "doc:manage_access" | "doc:manage_fields" | "doc:read_audit"
    )
}

/// What the differential runs hit, to show the cases are really covered.
#[derive(Default, Debug)]
struct Seen {
    row_checks: usize,
    allowed: usize,
    filters: usize,
    with_condition: usize,
    not_over_comparison: usize,
    null_rows_under_not: usize,
    ids_in_rows: usize,
    private_in_private: usize,
    delegation_denies: usize,
    org_owner_allows: usize,
    gone_role_denies: usize,
    group_decisions: usize,
    agent_outside_reach: usize,
    max_path: usize,
}

/// `list_filter` ≡ `check` for every asker, action and row of both tenants.
fn differential(seed: u64, w: &World, seen: &mut Seen) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let paths = Paths::of(&w.tenants);
    for t in &w.tenants {
        let rows: Vec<&Node> = t.rows().collect();
        for (p, actors) in askers() {
            for action in ACTIONS {
                let f = pdp
                    .list_filter(&list_req(t, &p, &actors, action), &paths)
                    .unwrap_or_else(|e| panic!("seed {seed}: list_filter failed: {e}"));
                seen.filters += 1;
                if let Some(c) = &f.condition {
                    seen.with_condition += 1;
                    if has_not_over_comparison(c) {
                        seen.not_over_comparison += 1;
                    }
                }
                for row in &rows {
                    let d = pdp.check(&check_req(t, &p, &actors, action, row)).unwrap();
                    let listed = row_matches(&f, row);
                    assert_eq!(
                        d.is_allowed(),
                        listed,
                        "seed {seed}: {} lists {} = {listed} but check says {:?} ({}) for {p} {actors:?} {action}\nfilter: {}\nrow: {:?}",
                        t.key.tid,
                        row.entry,
                        d.effect,
                        d.reason,
                        serde_json::to_string(&f).unwrap(),
                        row
                    );
                    count(seen, t, &f, row, &d, &actors);
                }
            }
        }
    }
}

fn count(
    seen: &mut Seen,
    t: &Tenant,
    f: &crate::ListFilter,
    row: &Node,
    d: &Decision,
    actors: &[Principal],
) {
    seen.row_checks += 1;
    seen.max_path = seen.max_path.max(row.path.len());
    if d.is_allowed() {
        seen.allowed += 1;
        if f.ids_in.contains(&row.entry.id) {
            seen.ids_in_rows += 1;
        }
        if d.reason.as_str().contains("org owner") {
            seen.org_owner_allows += 1;
        }
    }
    if f.condition.as_ref().is_some_and(has_not_over_comparison) && row.attrs.len() < 5 {
        seen.null_rows_under_not += 1;
    }
    let private: Vec<&crate::PathEntry> = row
        .path
        .iter()
        .filter(|a| t.data.private_scopes.contains(a))
        .collect();
    if private.len() >= 2 {
        seen.private_in_private += 1;
    }
    match d.reason.known_code() {
        Some(ReasonCode::DelegationOverlap) if !actors.is_empty() => seen.delegation_denies += 1,
        Some(ReasonCode::NoRole) if d.reason.as_str().contains("gone") => {
            seen.gone_role_denies += 1
        }
        Some(ReasonCode::OutsideAiReach) => seen.agent_outside_reach += 1,
        _ => {}
    }
    if d.rule_ids.iter().any(|r| r.as_str().starts_with("ra_g")) {
        seen.group_decisions += 1;
    }
}

/// No cross-tenant grant: a request of one tenant on a resource of the other
/// is always denied, and one tenant's data never changes the other's
/// decisions or filters.
fn no_cross_tenant(seed: u64, w: &World) {
    let both = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let paths = Paths::of(&w.tenants);
    for (i, t) in w.tenants.iter().enumerate() {
        let other = &w.tenants[1 - i];
        let alone = pdp_of(&w.model, &[t]);
        for (p, actors) in askers() {
            for action in ACTIONS {
                for row in other.rows() {
                    let d = both.check(&check_req(t, &p, &actors, action, row)).unwrap();
                    assert_eq!(d.effect, Effect::Deny, "seed {seed}: cross-tenant allow");
                    assert_eq!(d.reason.known_code(), Some(ReasonCode::TenantMismatch));
                    assert!(d.field_mask.is_empty());
                }
                for row in t.rows() {
                    let r = check_req(t, &p, &actors, action, row);
                    assert_eq!(both.check(&r), alone.check(&r), "seed {seed}");
                }
                let lr = list_req(t, &p, &actors, action);
                assert_eq!(
                    both.list_filter(&lr, &paths),
                    alone.list_filter(&lr, &paths),
                    "seed {seed}"
                );
            }
        }
    }
}

fn names(d: &Decision, write: bool) -> BTreeSet<String> {
    let v = if write {
        d.field_mask.write()
    } else {
        d.field_mask.read()
    };
    v.iter().map(ToString::to_string).collect()
}

/// Delegation ≤ person AND agent: the delegated decision is the overlap of
/// the person's and every actor's own decisions; admin keys and owner-only
/// actions never pass.
fn delegation(seed: u64, w: &World) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    for t in &w.tenants {
        for (p, actors) in askers().into_iter().filter(|(_, a)| !a.is_empty()) {
            for action in ACTIONS {
                for row in t.rows() {
                    let d = pdp.check(&check_req(t, &p, &actors, action, row)).unwrap();
                    let own: Vec<Decision> = core::iter::once(&p)
                        .chain(&actors)
                        .map(|x| pdp.check(&check_req(t, x, &[], action, row)).unwrap())
                        .collect();
                    let ctx = format!("seed {seed}: {p} {actors:?} {action} {}", row.entry);
                    if owner_only(action) {
                        assert_eq!(d.effect, Effect::Deny, "{ctx}");
                    } else {
                        assert_eq!(
                            d.is_allowed(),
                            own.iter().all(Decision::is_allowed),
                            "{ctx}"
                        );
                    }
                    let min = own.iter().map(|o| o.level).min().unwrap_or(Level::None);
                    assert_eq!(d.level, min, "{ctx}");
                    for write in [false, true] {
                        let both = own
                            .iter()
                            .map(|o| names(o, write))
                            .reduce(|a, b| a.intersection(&b).cloned().collect())
                            .unwrap_or_default();
                        assert_eq!(names(&d, write), both, "{ctx}");
                    }
                    for o in &own[1..] {
                        if owner_only(action) {
                            assert_eq!(o.effect, Effect::Deny, "{ctx}: an agent holds {action}");
                        }
                    }
                }
            }
        }
    }
}

/// `true` if `new` gives nothing that `old` does not.
fn not_wider(old: Option<&Decision>, new: Option<&Decision>) -> bool {
    let Some(new) = new else { return true };
    let Some(old) = old else {
        return !new.is_allowed() && new.level == Level::None;
    };
    (old.is_allowed() || !new.is_allowed())
        && new.level <= old.level
        && names(new, false).is_subset(&names(old, false))
        && names(new, true).is_subset(&names(old, true))
}

/// No widening: when the model diff says a change is not widening, no
/// decision gets wider. This ties the diff of ADR-0012 to the evaluator.
fn no_widening(seed: u64, w: &World, widening: &mut usize, compared: &mut usize) {
    let mut rng = Rng::new(seed ^ 0x5eed_c4a6_e000);
    let spec = w.spec.mutate(&mut rng);
    let Ok(new_model) = Model::from_toml(&spec.render()) else {
        return;
    };
    let d = diff(&w.model, &new_model).unwrap();
    if d.is_widening() {
        *widening += 1;
        return;
    }
    *compared += 1;
    let t = &w.tenants[0];
    let old = pdp_of(&w.model, &[t]);
    let new = pdp_of(&Arc::new(new_model), &[t]);
    for (p, actors) in askers() {
        for action in ACTIONS {
            for row in t.rows() {
                let r = check_req(t, &p, &actors, action, row);
                let (o, n) = (old.check(&r).ok(), new.check(&r).ok());
                assert!(
                    not_wider(o.as_ref(), n.as_ref()),
                    "seed {seed}: a {:?} diff widened {p} {actors:?} {action} on {}\nold: {o:?}\nnew: {n:?}\ndiff: {:?}\nold manifest:\n{}\nnew manifest:\n{}",
                    d.class(),
                    row.entry,
                    d.changes(),
                    w.spec.render(),
                    spec.render()
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn tm10_list_filter_returns_exactly_the_rows_check_allows(seed in any::<u64>()) {
        let w = world(seed);
        differential(seed, &w, &mut Seen::default());
    }

    #[test]
    fn tm05_no_cross_tenant_grant(seed in any::<u64>()) {
        no_cross_tenant(seed, &world(seed));
    }

    #[test]
    fn tm03_delegation_is_at_most_person_and_agent(seed in any::<u64>()) {
        delegation(seed, &world(seed));
    }

    #[test]
    fn tm08_a_change_the_diff_calls_safe_never_widens(seed in any::<u64>()) {
        no_widening(seed, &world(seed), &mut 0, &mut 0);
    }
}

/// The differential test on fixed seeds, with counts that show every case
/// of the week-1 spike is hit: deep paths, private inside private, groups,
/// gone roles, conditions with `not` on null fields, the agent overlap, the
/// org owner and assignments on the row itself.
#[test]
fn tm10_the_differential_test_hits_every_case() {
    let mut seen = Seen::default();
    for seed in 1..=40 {
        differential(seed, &world(seed), &mut seen);
    }
    eprintln!("{seen:#?}");
    assert!(seen.row_checks > 100_000, "{seen:?}");
    assert!(seen.allowed > 1_000, "{seen:?}");
    assert!(seen.with_condition > 100, "{seen:?}");
    assert!(seen.not_over_comparison > 10, "{seen:?}");
    assert!(seen.null_rows_under_not > 1_000, "{seen:?}");
    assert!(seen.ids_in_rows > 0, "{seen:?}");
    assert!(seen.private_in_private > 1_000, "{seen:?}");
    assert!(seen.delegation_denies > 100, "{seen:?}");
    assert!(seen.org_owner_allows > 0, "{seen:?}");
    assert!(seen.gone_role_denies > 0, "{seen:?}");
    assert!(seen.group_decisions > 100, "{seen:?}");
    assert!(seen.agent_outside_reach > 0, "{seen:?}");
    assert!(seen.max_path >= 31, "{seen:?}");
}

/// The no-widening property on fixed seeds compares a fair share of
/// changes (the rest the diff calls widening, or they do not compile).
#[test]
fn tm08_the_no_widening_test_compares_many_changes() {
    let (mut widening, mut compared) = (0, 0);
    for seed in 1..=120 {
        no_widening(seed, &world(seed), &mut widening, &mut compared);
    }
    eprintln!("compared {compared}, widening {widening}");
    assert!(compared >= 30, "compared {compared}, widening {widening}");
    assert!(widening >= 10, "compared {compared}, widening {widening}");
}
