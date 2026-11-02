//! The property tests of the library gate (SECURITY.md, ROADMAP Phase A):
//! `list_filter` ≡ `check` (the differential test), no cross-tenant grant,
//! delegation ≤ person AND agent, and no widening.
//!
//! Each case is one random world (testgen): a model, two tenants whose
//! resource ids are the same strings, groups, private scopes inside private
//! scopes, field rules, conditions with `not` over often-null fields, gone
//! roles, roles given to the wrong kind of subject, scopes of a type that is
//! not a container, ids reused across types and rows one level too deep.
//!
//! `check` is also compared with a reference evaluator (`testref`) that
//! shares no code with it, and `write_check` with the field mask of `check`.
//! The two searches are compared with `check` (`search_agrees`).

use std::collections::BTreeSet;
use std::sync::Arc;

use proptest::prelude::*;
use tutela_contracts::decision::{Decision, Effect, ReasonCode};
use tutela_contracts::keys::{ActionKey, FieldName};
use tutela_contracts::level::Level;
use tutela_contracts::principal::{Principal, PrincipalKind};

use crate::filter::{FilterExpr, ListFilter};
use crate::model::{Model, diff};
use crate::testgen::{
    DATA_FIELDS, Node, Paths, Rng, Tenant, World, has_not_over_comparison, principals, row_matches,
    world,
};
use crate::testref::expected;
use crate::tests_check::{agent, user};
use crate::{
    Attrs, CheckRequest, ListFilterRequest, PathEntry, Pdp, PdpError, ScopePathProblem,
    SubjectSearchRequest, WriteCheckRequest,
};

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
        "doc:seal"
            | "doc:manage_access"
            | "doc:manage_fields"
            | "doc:read_audit"
            | "doc:approve_move"
    )
}

/// The decision, or `None` for a row `check` refuses: one with 33
/// ancestors. Any other error fails the test.
fn decide(pdp: &Pdp, r: &CheckRequest) -> Option<Decision> {
    match pdp.check(r) {
        Ok(d) => Some(d),
        Err(PdpError::PathTooLong) => None,
        Err(e) => panic!("check failed: {e}"),
    }
}

fn is_allowed(d: Option<&Decision>) -> bool {
    d.is_some_and(Decision::is_allowed)
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
    under_non_container: usize,
    too_deep_rows: usize,
    reused_ids: usize,
}

/// `list_filter` ≡ `check` for every asker, action and row of both tenants.
fn differential(seed: u64, w: &World, seen: &mut Seen) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let paths = Paths::of(&w.tenants);
    let indexed = Paths {
        indexed: true,
        ..Paths::of(&w.tenants)
    };
    for t in &w.tenants {
        let rows: Vec<&Node> = t.rows().collect();
        for (p, actors) in askers() {
            for action in &w.spec.actions() {
                let action = action.as_str();
                let f = pdp
                    .list_filter(&list_req(t, &p, &actors, action), &paths)
                    .unwrap_or_else(|e| panic!("seed {seed}: list_filter failed: {e}"));
                // A provider that answers `below` gives the same filter.
                let g = pdp
                    .list_filter(&list_req(t, &p, &actors, action), &indexed)
                    .unwrap_or_else(|e| panic!("seed {seed}: indexed list_filter failed: {e}"));
                assert_eq!(f, g, "seed {seed}: {p} {actors:?} {action}");
                seen.filters += 1;
                if let Some(c) = &f.condition {
                    seen.with_condition += 1;
                    if has_not_over_comparison(c) {
                        seen.not_over_comparison += 1;
                    }
                }
                for row in &rows {
                    let d = decide(&pdp, &check_req(t, &p, &actors, action, row));
                    let listed = row_matches(&f, row);
                    assert_eq!(
                        is_allowed(d.as_ref()),
                        listed,
                        "seed {seed}: {} lists {} = {listed} but check says {:?} for {p} {actors:?} {action}\nfilter: {}\nrow: {:?}",
                        t.key.tid,
                        row.entry,
                        d.as_ref().map(|d| (d.effect, d.reason.to_string())),
                        serde_json::to_string(&f).unwrap(),
                        row
                    );
                    count(seen, t, &f, row, d.as_ref(), &actors);
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
    d: Option<&Decision>,
    actors: &[Principal],
) {
    seen.row_checks += 1;
    seen.max_path = seen.max_path.max(row.path.len());
    if row.path.iter().any(|a| a.type_name.as_str() == "box") {
        seen.under_non_container += 1;
    }
    if row.entry.id.as_str().starts_with('n') {
        seen.reused_ids += 1;
    }
    let Some(d) = d else {
        seen.too_deep_rows += 1;
        return;
    };
    if d.is_allowed() {
        seen.allowed += 1;
        if f.ids_in.contains(&row.entry.id) {
            seen.ids_in_rows += 1;
        }
        if d.reason.as_str().contains("org owner") {
            seen.org_owner_allows += 1;
        }
    }
    if f.condition.as_ref().is_some_and(has_not_over_comparison)
        && row.attrs.values().any(|v| *v == crate::AttrValue::Null)
    {
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
            for action in &w.spec.actions() {
                let action = action.as_str();
                for row in other.rows() {
                    let Some(d) = decide(&both, &check_req(t, &p, &actors, action, row)) else {
                        continue;
                    };
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
            for action in &w.spec.actions() {
                let action = action.as_str();
                for row in t.rows().filter(|r| r.path.len() <= crate::MAX_PATH) {
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
    let actions: BTreeSet<String> = w.spec.actions().into_iter().chain(spec.actions()).collect();
    for (p, actors) in askers() {
        for action in &actions {
            let action = action.as_str();
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

/// `check` agrees with the reference evaluator, which shares no code with
/// it: effect, level and both field masks.
fn matches_reference(seed: u64, w: &World, compared: &mut usize) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    for t in &w.tenants {
        for (p, actors) in askers() {
            for action in &w.spec.actions() {
                for row in t.rows() {
                    let r = check_req(t, &p, &actors, action, row);
                    let want = expected(&w.model, &t.data, &r);
                    let got = decide(&pdp, &r).map(|d| crate::testref::Expected {
                        allowed: d.is_allowed(),
                        level: d.level,
                        read: names(&d, false),
                        write: names(&d, true),
                    });
                    assert_eq!(
                        got, want,
                        "seed {seed}: check and the reference disagree for {p} {actors:?} {action} on {}",
                        row.entry
                    );
                    *compared += 1;
                }
            }
        }
    }
}

/// A scope-path provider miss fails the list exactly when the missing scope
/// is one the filter needs, and never changes a list otherwise. Each world
/// tries a missing private scope and a missing assigned scope.
fn provider_misses(seed: u64, w: &World, failed: &mut usize) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let full = Paths::of(&w.tenants);
    let mut rng = Rng::new(seed ^ 0x0000_0f1a_0000);
    for t in &w.tenants {
        let private: Vec<&crate::PathEntry> = t.data.private_scopes.iter().collect();
        let assigned: Vec<&crate::PathEntry> = t
            .data
            .bindings
            .iter()
            .map(|b| &b.scope)
            .filter(|s| !s.is_org())
            .collect();
        for pool in [private, assigned] {
            if pool.is_empty() {
                continue;
            }
            let gone = (*rng.pick(&pool)).clone();
            let mut miss = Paths::of(&w.tenants);
            miss.missing.insert(gone.clone());
            for (p, actors) in askers() {
                for action in ["doc:read", "doc:write"] {
                    miss.asked.borrow_mut().clear();
                    let lr = list_req(t, &p, &actors, action);
                    let got = pdp.list_filter(&lr, &miss);
                    if miss.asked.borrow().contains(&gone) {
                        *failed += 1;
                        assert_eq!(
                            got,
                            Err(PdpError::ScopePath {
                                scope: gone.clone(),
                                problem: ScopePathProblem::NotFound
                            }),
                            "seed {seed}"
                        );
                    } else {
                        assert_eq!(got, pdp.list_filter(&lr, &full), "seed {seed}");
                    }
                }
            }
        }
    }
}

/// `write_check` agrees with `check`: a data field is in
/// `field_mask.write` exactly when `write_check` allows changing it alone;
/// a write of every field gives the same verdicts as the writes one by one;
/// and a delegated write is allowed only when the person and every actor
/// may make it alone.
fn write_check_agrees(seed: u64, w: &World) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let wreq = |t: &Tenant, p: &Principal, actors: &[Principal], row: &Node, fields: &[&str]| {
        let mut new_attrs = Attrs::new();
        for f in fields {
            let v = w
                .spec
                .sample_value(f)
                .unwrap_or(crate::AttrValue::String("v".into()));
            new_attrs.insert(FieldName::parse(f).unwrap(), v);
        }
        WriteCheckRequest {
            tenant: t.key.clone(),
            subject: p.clone(),
            actors: actors.to_vec(),
            resource: row.resource(),
            new_attrs,
            new_path: None,
            at_least_revision: None,
        }
    };
    for t in &w.tenants {
        for row in t.rows().filter(|r| r.path.len() <= crate::MAX_PATH) {
            for (p, actors) in askers() {
                let c = pdp
                    .check(&check_req(t, &p, &actors, "doc:read", row))
                    .unwrap();
                let all = pdp
                    .write_check(&wreq(t, &p, &actors, row, &DATA_FIELDS))
                    .unwrap();
                for f in &DATA_FIELDS {
                    let one = pdp.write_check(&wreq(t, &p, &actors, row, &[*f])).unwrap();
                    let ctx = format!("seed {seed}: {p} {actors:?} {f} on {}", row.entry);
                    let allowed = one.effect == Effect::Allow;
                    assert_eq!(
                        c.field_mask.can_write(&FieldName::parse(f).unwrap()),
                        allowed,
                        "{ctx}: mask {:?}, write_check {:?}",
                        c.field_mask,
                        one.fields
                    );
                    let in_all = all.fields.iter().find(|v| v.field.as_str() == *f);
                    assert_eq!(
                        in_all.map(|v| v.effect),
                        Some(one.fields[0].effect),
                        "{ctx}"
                    );
                    if allowed && !actors.is_empty() {
                        for x in core::iter::once(&p).chain(&actors) {
                            let alone = pdp.write_check(&wreq(t, x, &[], row, &[*f])).unwrap();
                            assert_eq!(alone.effect, Effect::Allow, "{ctx}: {x} alone");
                        }
                    }
                }
                assert_eq!(
                    all.effect == Effect::Allow,
                    all.fields.iter().all(|v| v.effect == Effect::Allow),
                    "seed {seed}"
                );
            }
        }
    }
}

/// Every page of a resource search, with a small limit so that paging is
/// part of what is tested. A resource never comes twice.
fn all_resources(
    pdp: &Pdp,
    req: &ListFilterRequest,
    paths: &Paths,
) -> (ListFilter, Vec<PathEntry>) {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let page = pdp
            .search_resources(req, paths, after.as_ref(), 3)
            .unwrap_or_else(|e| panic!("search failed: {e}"));
        out.extend(page.results);
        after = page.next;
        if after.is_none() {
            let sorted: BTreeSet<_> = out.iter().collect();
            assert_eq!(sorted.len(), out.len(), "a resource came twice");
            return (page.filter, out);
        }
    }
}

fn all_subjects(pdp: &Pdp, req: &SubjectSearchRequest) -> Vec<Principal> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let page = pdp
            .search_subjects(req, after.as_ref(), 2)
            .unwrap_or_else(|e| panic!("search failed: {e}"));
        out.extend(page.results);
        after = page.next;
        if after.is_none() {
            return out;
        }
    }
}

/// `true` if the filter's answer can depend on a field value.
fn reads_a_field(e: &FilterExpr) -> bool {
    match e {
        FilterExpr::True
        | FilterExpr::False
        | FilterExpr::IdIn { .. }
        | FilterExpr::Under { .. } => false,
        FilterExpr::And { args } | FilterExpr::Or { args } => args.iter().any(reads_a_field),
        FilterExpr::Not { arg } => reads_a_field(arg),
        _ => true,
    }
}

#[derive(Default)]
struct SearchSeen {
    listed: usize,
    exact: usize,
    hidden_by_a_field: usize,
    subjects_listed: usize,
    subjects_compared: usize,
}

/// A listed resource is one `check` allows, whatever its field values are.
/// When the filter reads no field, the two agree in both directions.
/// A subject search lists exactly the principals `check` allows.
fn search_agrees(seed: u64, w: &World, seen: &mut SearchSeen) {
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    let paths = Paths {
        indexed: true,
        ..Paths::of(&w.tenants)
    };
    for t in &w.tenants {
        let rows: Vec<&Node> = t.rows().collect();
        let values: Vec<Attrs> = rows.iter().take(6).map(|r| r.resource().attrs).collect();
        for (p, actors) in askers() {
            for action in &w.spec.actions() {
                let action = action.as_str();
                let (filter, listed) =
                    all_resources(&pdp, &list_req(t, &p, &actors, action), &paths);
                let any_field = filter.condition.as_ref().is_some_and(reads_a_field);
                for row in &rows {
                    let req = check_req(t, &p, &actors, action, row);
                    let allowed = is_allowed(decide(&pdp, &req).as_ref());
                    if listed.contains(&row.entry) {
                        seen.listed += 1;
                        assert!(
                            allowed,
                            "seed {seed}: search names {} but check denies {p} {actors:?} {action}",
                            row.entry
                        );
                        for attrs in &values {
                            let mut other = req.clone();
                            other.resource.attrs = attrs.clone();
                            assert!(
                                is_allowed(decide(&pdp, &other).as_ref()),
                                "seed {seed}: search names {} but other field values deny it",
                                row.entry
                            );
                        }
                    } else if any_field {
                        seen.hidden_by_a_field += usize::from(allowed);
                    } else {
                        seen.exact += 1;
                        assert!(
                            !allowed,
                            "seed {seed}: search leaves out {}, which check allows for {p} {actors:?} {action}",
                            row.entry
                        );
                    }
                }
            }
        }
        for row in rows
            .iter()
            .filter(|r| r.path.len() <= crate::MAX_PATH)
            .take(12)
        {
            for action in &w.spec.actions() {
                for kind in [
                    PrincipalKind::User,
                    PrincipalKind::Agent,
                    PrincipalKind::ServiceAccount,
                ] {
                    let listed = all_subjects(
                        &pdp,
                        &SubjectSearchRequest {
                            tenant: t.key.clone(),
                            kind,
                            action: ActionKey::parse(action).unwrap(),
                            resource: row.resource(),
                            at_least_revision: None,
                        },
                    );
                    seen.subjects_listed += listed.len();
                    for p in &listed {
                        assert_eq!(p.kind(), kind);
                        let d = decide(&pdp, &check_req(t, p, &[], action, row));
                        assert!(
                            is_allowed(d.as_ref()),
                            "seed {seed}: search names {p}, and check denies {action} on {}",
                            row.entry
                        );
                    }
                    for p in principals().iter().filter(|p| p.kind() == kind) {
                        seen.subjects_compared += 1;
                        let d = decide(&pdp, &check_req(t, p, &[], action, row));
                        assert_eq!(
                            listed.contains(p),
                            is_allowed(d.as_ref()),
                            "seed {seed}: search and check disagree on {p} {action} {}",
                            row.entry
                        );
                    }
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn check_matches_the_reference_evaluator(seed in any::<u64>()) {
        matches_reference(seed, &world(seed), &mut 0);
    }

    #[test]
    fn tm10_a_provider_miss_fails_exactly_the_lists_that_need_it(seed in any::<u64>()) {
        provider_misses(seed, &world(seed), &mut 0);
    }

    #[test]
    fn write_check_agrees_with_the_field_mask(seed in any::<u64>()) {
        write_check_agrees(seed, &world(seed));
    }

    #[test]
    fn tm10_list_filter_returns_exactly_the_rows_check_allows(seed in any::<u64>()) {
        let w = world(seed);
        differential(seed, &w, &mut Seen::default());
    }

    #[test]
    fn tm10_search_agrees_with_check(seed in any::<u64>()) {
        search_agrees(seed, &world(seed), &mut SearchSeen::default());
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
/// The search test means nothing if every world is empty.
#[test]
fn tm10_the_search_test_compares_enough() {
    let mut seen = SearchSeen::default();
    for seed in 0..12 {
        search_agrees(seed, &world(seed), &mut seen);
    }
    assert!(seen.listed > 200, "{}", seen.listed);
    assert!(seen.exact > 200, "{}", seen.exact);
    assert!(seen.hidden_by_a_field > 0, "{}", seen.hidden_by_a_field);
    assert!(seen.subjects_listed > 50, "{}", seen.subjects_listed);
    assert!(seen.subjects_compared > 500, "{}", seen.subjects_compared);
}

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
    assert!(seen.max_path >= 33, "{seen:?}");
    assert!(seen.under_non_container > 1_000, "{seen:?}");
    assert!(seen.too_deep_rows > 0, "{seen:?}");
    assert!(seen.reused_ids > 1_000, "{seen:?}");
}

/// `true` if some group of the tenant sits in two other groups, so its
/// closure is the union of both holders' closures.
fn has_a_group_with_two_holders(t: &Tenant) -> bool {
    t.data.groups.iter().any(|g| {
        let inner = crate::Member::Group(g.key.clone());
        t.data
            .groups
            .iter()
            .filter(|h| h.members.contains(&inner))
            .count()
            >= 2
    })
}

/// The reference comparison and the provider-miss test on fixed seeds, with
/// counts.
#[test]
fn the_reference_and_miss_tests_compare_enough() {
    let (mut compared, mut failed, mut two_holders) = (0, 0, 0);
    for seed in 1..=20 {
        let w = world(seed);
        matches_reference(seed, &w, &mut compared);
        provider_misses(seed, &w, &mut failed);
        two_holders += w
            .tenants
            .iter()
            .filter(|t| has_a_group_with_two_holders(t))
            .count();
    }
    eprintln!(
        "reference comparisons {compared}, lists failed by a miss {failed}, \
         tenants with a group in two groups {two_holders}"
    );
    assert!(compared > 50_000, "{compared}");
    assert!(failed > 100, "{failed}");
    assert!(two_holders >= 3, "{two_holders}");
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
