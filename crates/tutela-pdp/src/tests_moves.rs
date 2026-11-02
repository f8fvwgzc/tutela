//! Moves and links across scopes (PERMISSION-MODEL.md 9, 10; ADR-0025).
//!
//! The property tests compare the verdict with what `check` really says
//! before and after the move, for every principal and every row below the
//! moved item, so a bug in the comparison cannot hide behind itself.

use std::collections::BTreeSet;
use std::sync::Arc;

use proptest::prelude::*;
use tutela_contracts::decision::{Decision, Effect};
use tutela_contracts::keys::{ActionKey, FieldName};
use tutela_contracts::principal::Principal;

use crate::model::{GroupKey, Model};
use crate::testgen::{Node, Rng, Tenant, World, principals, world};
use crate::tests_check::{agent, binding, direct, entry, org_id, tenant, user};
use crate::tests_props::{Seen, askers, check_req, differential, pdp_of};
use crate::{
    AttrValue, Attrs, BoundaryRule, Group, LinkVerdict, LinksFrom, MAX_MOVE_CANDIDATES, Member,
    MoveDecision, MoveOutcome, MoveRule, OnLooser, PathEntry, Pdp, PdpError, ResourceRef, Subject,
    TenantData, WriteCheckRequest,
};

const MANIFEST: &str = r#"
version = 1
[app]
name = "mv"

[types.team]
parent = "org"
container = true

[types.project]
parent = "team"
container = true

[types.issue]
parent = "project"

[types.issue.fields]
title = { sensitivity = "internal" }
budget = { sensitivity = "confidential" }
status = { sensitivity = "internal", grants_access = true }

[roles.lead]
grants = { team = "read", project = "write", issue = "write" }

[roles.gatekeeper]
grants = { project = "read", issue = "read", "project:approve_move" = true }

[roles.writer_when_open]
grants = { team = "read", project = "read", issue = "write" }

[roles.writer]
grants = { team = "read", project = "read", issue = "write" }

[[conditions]]
role = "writer_when_open"
type = "issue"
when = { eq = { field = "status", value = "open" } }
else = "read"

[[field_rules]]
field = "issue.budget"
role = "lead"
max = "read"
"#;

const DANA: u32 = 1; // org owner
const OWNER1: u32 = 2; // owner of p1
const OWNER2: u32 = 3; // owner of p2
const MEMBER: u32 = 4; // member of t1, so of p1 and p2
const VIEWER: u32 = 5; // viewer of t1
const LEAD: u32 = 6; // lead of p2: reads budget there
const MEMBER2: u32 = 7; // member of t2, so of p3, p4 and p5

fn org() -> PathEntry {
    PathEntry::org(&org_id(1)).unwrap()
}

fn t1() -> PathEntry {
    entry("team", "t1")
}

fn t2() -> PathEntry {
    entry("team", "t2")
}

fn project(n: u32) -> PathEntry {
    entry("project", &format!("p{n}"))
}

fn under(p: u32) -> Vec<PathEntry> {
    let team = if p <= 2 { t1() } else { t2() };
    vec![project(p), team, org()]
}

fn data() -> TenantData {
    TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_d", direct(&user(DANA)), "owner", org()),
            binding("ra_o1", direct(&user(OWNER1)), "owner", project(1)),
            binding("ra_o2", direct(&user(OWNER2)), "owner", project(2)),
            binding("ra_m", direct(&user(MEMBER)), "member", t1()),
            binding("ra_v", direct(&user(VIEWER)), "viewer", t1()),
            binding("ra_l", direct(&user(LEAD)), "lead", project(2)),
            binding("ra_m2", direct(&user(MEMBER2)), "member", t2()),
            binding("ra_ag", direct(&agent(1)), "agent", project(2)),
        ],
        ..TenantData::default()
    }
}

fn pdp(data: TenantData) -> Pdp {
    let mut pdp = Pdp::new();
    let model = Arc::new(Model::from_toml(MANIFEST).unwrap());
    pdp.load(tenant(1), 1, model, data).unwrap();
    pdp
}

fn with_rule(scope: PathEntry, rule: BoundaryRule) -> Pdp {
    let mut d = data();
    d.boundaries.insert(scope, rule);
    pdp(d)
}

fn issue(path: Vec<PathEntry>) -> ResourceRef {
    ResourceRef {
        type_name: "issue".parse().unwrap(),
        id: "i-1".parse().unwrap(),
        path,
        attrs: Attrs::from([(FieldName::parse("status").unwrap(), AttrValue::Null)]),
    }
}

fn mv(p: &Principal, from: u32, to: u32) -> WriteCheckRequest {
    WriteCheckRequest {
        tenant: tenant(1),
        subject: p.clone(),
        actors: vec![],
        resource: issue(under(from)),
        new_attrs: Attrs::new(),
        new_path: Some(under(to)),
        new_links: vec![],
        approved_by: vec![],
        at_least_revision: None,
    }
}

fn verdict(pdp: &Pdp, r: &WriteCheckRequest) -> MoveDecision {
    pdp.write_check(r).unwrap().moved.unwrap()
}

#[test]
fn tm08_a_move_into_a_looser_scope_waits_for_the_source_owner() {
    let pdp = pdp(data());
    // At p2 the lead reads the budget and the owner of p2 gains the item.
    let mut r = mv(&user(MEMBER), 1, 2);
    let m = verdict(&pdp, &r);
    assert_eq!(m.outcome, MoveOutcome::NeedsApproval, "{m:?}");
    assert_eq!(m.effect, Effect::Deny);
    assert!(m.looser && m.complete);
    assert_eq!(m.approve_at, vec![project(1)]);
    assert_eq!(m.reason.code(), "approval_required");
    assert!(pdp.write_check(&r).unwrap().effect == Effect::Deny);
    assert!(m.gains.iter().any(|l| l.key == "issue.budget"
        && l.to == "read"
        && l.principals.contains(&user(LEAD).to_string())));

    // The owner of the target is not the source's owner.
    r.approved_by = vec![user(OWNER2)];
    assert_eq!(verdict(&pdp, &r).outcome, MoveOutcome::NeedsApproval);
    r.approved_by = vec![user(VIEWER), user(MEMBER)];
    assert_eq!(verdict(&pdp, &r).outcome, MoveOutcome::NeedsApproval);
    r.approved_by = vec![user(OWNER1)];
    let m = verdict(&pdp, &r);
    assert_eq!(m.outcome, MoveOutcome::Allowed, "{m:?}");
    assert!(m.looser);
    assert_eq!(pdp.write_check(&r).unwrap().effect, Effect::Allow);
}

#[test]
fn the_source_owner_approves_by_moving() {
    let pdp = pdp(data());
    // The owner of p1 has no write at p2, the org owner has both.
    let m = verdict(&pdp, &mv(&user(DANA), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Allowed, "{m:?}");
    assert!(m.looser);
    let m = verdict(&pdp, &mv(&user(OWNER1), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.reason.code(), "boundary_rule");
}

#[test]
fn an_owner_can_block_a_move_into_a_looser_scope() {
    let rule = BoundaryRule {
        on_looser: Some(OnLooser::Block),
        ..BoundaryRule::default()
    };
    let pdp = with_rule(project(1), rule);
    let m = verdict(&pdp, &mv(&user(DANA), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.reason.code(), "boundary_rule");
    assert!(m.rule_ids.iter().any(|r| r.as_str().contains("boundary:")));
}

#[test]
fn tm08_a_boundary_rule_stops_a_move_on_its_own_side() {
    let nobody = |out: bool| BoundaryRule {
        moves_out: out.then_some(MoveRule::Nobody),
        moves_in: (!out).then_some(MoveRule::Nobody),
        ..BoundaryRule::default()
    };
    for (scope, out, stopped) in [
        (project(1), true, true),
        (project(2), false, true),
        // The rule of the other side says nothing about this move.
        (project(1), false, false),
        (project(2), true, false),
    ] {
        let pdp = with_rule(scope.clone(), nobody(out));
        let m = verdict(&pdp, &mv(&user(DANA), 1, 2));
        assert_eq!(
            m.outcome == MoveOutcome::Refused,
            stopped,
            "{scope} out={out}: {m:?}"
        );
    }
}

#[test]
fn tm08_owners_of_a_scope_hold_approve_move() {
    let owners = BoundaryRule {
        moves_out: Some(MoveRule::Owners),
        ..BoundaryRule::default()
    };
    let pdp = with_rule(project(1), owners);
    let m = verdict(&pdp, &mv(&user(MEMBER), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.reason.code(), "boundary_rule");
    // A viewer cannot write the item, whatever the rule.
    let m = verdict(&pdp, &mv(&user(VIEWER), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Refused);
    assert_eq!(m.reason.code(), "level_too_low");
}

#[test]
fn a_scope_further_out_adds_a_rule_only_when_it_set_one() {
    // p4 and p5 share t2, so t2 is not crossed.
    let pdp = with_rule(
        t2(),
        BoundaryRule {
            moves_out: Some(MoveRule::Nobody),
            ..BoundaryRule::default()
        },
    );
    assert_eq!(
        verdict(&pdp, &mv(&user(MEMBER2), 4, 5)).outcome,
        MoveOutcome::Allowed
    );
    // Leaving t2 crosses it.
    let m = verdict(&pdp, &mv(&user(DANA), 4, 1));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.left, vec![project(4), t2()]);
    assert_eq!(m.entered, vec![project(1), t1()]);
    // With no rule on the teams, the org owner may cross them.
    assert_ne!(
        verdict(&self::pdp(data()), &mv(&user(DANA), 4, 1)).outcome,
        MoveOutcome::Refused
    );
}

#[test]
fn across_teams_only_owners_of_both_sides() {
    let pdp = pdp(data());
    let mut both = data();
    both.bindings
        .push(binding("ra_x", direct(&user(MEMBER)), "member", t2()));
    let wide = self::pdp(both);
    // MEMBER may write on both sides, and still may not cross teams.
    let m = verdict(&wide, &mv(&user(MEMBER), 1, 4));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.reason.code(), "boundary_rule");
    assert_ne!(
        verdict(&pdp, &mv(&user(DANA), 1, 4)).outcome,
        MoveOutcome::Refused
    );
}

#[test]
fn a_move_that_gives_nobody_more_goes_through() {
    let pdp = pdp(data());
    let m = verdict(&pdp, &mv(&user(MEMBER2), 4, 5));
    assert_eq!(m.outcome, MoveOutcome::Allowed, "{m:?}");
    assert!(!m.looser && m.complete);
    assert!(m.gains.is_empty());
}

#[test]
fn tm09_approvals_never_pass_through_delegation() {
    let pdp = pdp(data());
    let mut r = mv(&user(DANA), 1, 2);
    r.actors = vec![agent(1)];
    let m = verdict(&pdp, &r);
    // The agent has no role at p1, so it cannot write the item.
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    // At p2 it may read only; an agent never approves.
    let mut r = mv(&user(MEMBER), 1, 2);
    r.approved_by = vec![agent(1)];
    assert_eq!(verdict(&pdp, &r).outcome, MoveOutcome::NeedsApproval);
}

/// Found by the property test: the principal below the moved item is on
/// neither path, and the rule it escapes sits above its assignment.
#[test]
fn tm08_a_rule_left_behind_counts_for_whoever_sits_below_the_moved_scope() {
    let mut d = data();
    let budget = "issue.title".parse().unwrap();
    d.field_rules.push(crate::ScopeFieldRule {
        id: "fr_1".parse().unwrap(),
        scope: t1(),
        field: budget,
        role: None,
        max: tutela_contracts::level::Level::None,
    });
    let pdp = pdp(d);
    let mut r = mv(&user(DANA), 1, 2);
    r.resource = ResourceRef {
        type_name: "project".parse().unwrap(),
        id: "p1".parse().unwrap(),
        path: vec![t1(), org()],
        attrs: Attrs::new(),
    };
    r.new_path = Some(vec![t2(), org()]);
    let m = verdict(&pdp, &r);
    assert!(m.looser, "{m:?}");
    assert!(
        m.gains
            .iter()
            .any(|l| l.kind == "role" && l.key == "issue.title"),
        "{m:?}"
    );
}

#[test]
fn a_comparison_that_stops_early_never_says_nobody_gains() {
    // Thousands of members of a group at t2, who keep what they have.
    let mut d = data();
    let users: Vec<Member> = (0..=u32::try_from(MAX_MOVE_CANDIDATES).unwrap())
        .map(|i| Member::Principal(user(100 + i)))
        .collect();
    let g = GroupKey::parse("everyone").unwrap();
    d.groups.push(Group {
        key: g.clone(),
        members: users,
    });
    d.bindings.push(crate::Binding {
        id: "ra_g".parse().unwrap(),
        subject: Subject::Group(g),
        role: crate::model::RoleKey::parse("viewer").unwrap(),
        scope: t2(),
    });
    let pdp = pdp(d);
    let m = verdict(&pdp, &mv(&user(MEMBER2), 4, 5));
    assert!(!m.complete, "{m:?}");
    assert!(m.looser);
    assert_eq!(m.outcome, MoveOutcome::NeedsApproval);
    assert_eq!(m.approve_at, vec![project(4)]);
}

#[test]
fn a_new_path_breaks_no_rule_of_a_path() {
    let pdp = pdp(data());
    let bad = |path: Vec<PathEntry>| {
        let mut r = mv(&user(DANA), 1, 2);
        r.new_path = Some(path);
        matches!(pdp.write_check(&r), Err(PdpError::InvalidInput { .. }))
    };
    assert!(bad(vec![]));
    assert!(bad(vec![project(2)]), "no org");
    assert!(bad(vec![t1(), org()]), "a team may not hold an issue");
    assert!(
        bad(vec![project(2), project(2), t1(), org()]),
        "an entry twice"
    );
    assert!(
        bad(vec![entry("issue", "i-1"), project(2), t1(), org()]),
        "under itself"
    );
    let mut r = mv(&user(DANA), 1, 2);
    r.resource = ResourceRef {
        type_name: "org".parse().unwrap(),
        id: org().id,
        path: vec![],
        attrs: Attrs::new(),
    };
    assert!(pdp.write_check(&r).is_err(), "an org has no parent");
}

#[test]
fn tm05_a_move_stays_in_its_tenant_and_its_org() {
    let mut d = data();
    d.orgs.insert(org_id(2));
    let pdp = pdp(d);
    let other = PathEntry::org(&org_id(3)).unwrap();
    let mut r = mv(&user(DANA), 1, 2);
    r.new_path = Some(vec![project(9), t1(), other]);
    let m = verdict(&pdp, &r);
    assert_eq!(m.outcome, MoveOutcome::Refused);
    assert_eq!(m.reason.code(), "tenant_mismatch");
    let mine = PathEntry::org(&org_id(2)).unwrap();
    r.new_path = Some(vec![project(9), t1(), mine]);
    let m = verdict(&pdp, &r);
    assert_eq!(m.outcome, MoveOutcome::Refused);
    assert_eq!(
        m.reason.as_str(),
        "boundary_rule: a move stays inside its org"
    );
}

#[test]
fn tm09_a_person_does_not_approve_through_an_agent() {
    // The agent may write on both sides, so only the approval is missing.
    let mut d = data();
    for (id, p) in [("ra_w1", 1), ("ra_w2", 2)] {
        d.bindings
            .push(binding(id, direct(&agent(2)), "lead", project(p)));
    }
    let pdp = pdp(d);
    let mut r = mv(&user(DANA), 1, 2);
    assert_eq!(verdict(&pdp, &r).outcome, MoveOutcome::Allowed);
    r.actors = vec![agent(2)];
    let m = verdict(&pdp, &r);
    assert_eq!(m.outcome, MoveOutcome::NeedsApproval, "{m:?}");
    // Naming the person as the approver is the service's word, and it holds.
    r.approved_by = vec![user(DANA)];
    assert_eq!(verdict(&pdp, &r).outcome, MoveOutcome::Allowed);
}

#[test]
fn a_gain_that_depends_on_a_condition_counts() {
    // User 8 writes open issues in t1, and every issue in t2. A row that is
    // not open goes from read to write, and the row is not known here.
    let mut d = data();
    d.bindings
        .push(binding("ra_c", direct(&user(8)), "writer_when_open", t1()));
    d.bindings
        .push(binding("ra_w", direct(&user(8)), "writer", t2()));
    let pdp = pdp(d);
    let mut r = mv(&user(DANA), 1, 4);
    r.resource = ResourceRef {
        type_name: "project".parse().unwrap(),
        id: "p1".parse().unwrap(),
        path: vec![t1(), org()],
        attrs: Attrs::new(),
    };
    r.new_path = Some(vec![t2(), org()]);
    let m = verdict(&pdp, &r);
    let line = m
        .gains
        .iter()
        .find(|l| l.key == "issue" && l.principals.contains(&user(8).to_string()))
        .unwrap_or_else(|| panic!("no gain on issue: {m:?}"));
    assert!(line.conditional);
    assert_eq!((line.from.as_str(), line.to.as_str()), ("read", "write"));
}

#[test]
fn a_new_child_needs_write_on_its_new_parent() {
    // `moves_in = owners` lets the gatekeeper past the rule, not past this.
    let mut d = data();
    d.bindings.push(binding(
        "ra_g",
        direct(&user(MEMBER)),
        "gatekeeper",
        project(2),
    ));
    d.boundaries.insert(
        project(2),
        BoundaryRule {
            moves_in: Some(MoveRule::Owners),
            ..BoundaryRule::default()
        },
    );
    let pdp = pdp(d);
    let m = verdict(&pdp, &mv(&user(MEMBER), 1, 2));
    assert_eq!(m.outcome, MoveOutcome::Refused, "{m:?}");
    assert_eq!(m.reason.code(), "level_too_low");
}

#[test]
fn a_path_that_does_not_change_crosses_nothing() {
    let pdp = pdp(data());
    let m = verdict(&pdp, &mv(&user(MEMBER), 1, 1));
    assert_eq!(m.outcome, MoveOutcome::Allowed);
    assert!(m.left.is_empty() && m.entered.is_empty() && !m.looser);
}

fn link(p: &Principal, from: u32, to: u32) -> WriteCheckRequest {
    let mut target = issue(under(to));
    target.id = "i-2".parse().unwrap();
    WriteCheckRequest {
        new_path: None,
        new_links: vec![target],
        ..mv(p, from, to)
    }
}

fn link_verdict(pdp: &Pdp, r: &WriteCheckRequest) -> LinkVerdict {
    pdp.write_check(r).unwrap().links.pop().unwrap()
}

#[test]
fn tm09_links_never_grant_and_follow_the_targets_rule() {
    let pdp = pdp(data());
    let v = link_verdict(&pdp, &link(&user(MEMBER), 1, 2));
    assert_eq!(v.effect, Effect::Allow, "{v:?}");
    // Writing the source needs write; a viewer reads both sides.
    let v = link_verdict(&pdp, &link(&user(VIEWER), 1, 2));
    assert_eq!(v.effect, Effect::Deny);
    assert_eq!(v.reason.code(), "level_too_low");
    // A link to what you cannot open says nothing about why.
    let v = link_verdict(&pdp, &link(&user(MEMBER), 1, 4));
    assert_eq!(v.effect, Effect::Deny);
    assert_eq!(v.reason.as_str(), "not_allowed");
    assert!(v.rule_ids.is_empty());
    assert_eq!(
        pdp.write_check(&link(&user(MEMBER), 1, 4)).unwrap().effect,
        Effect::Deny
    );
}

#[test]
fn links_from_says_who_may_link_in() {
    let rule = |l| BoundaryRule {
        links_from: Some(l),
        ..BoundaryRule::default()
    };
    let target = project(2);
    let team = with_rule(target.clone(), rule(LinksFrom::Team));
    let nobody = with_rule(target.clone(), rule(LinksFrom::Nobody));
    let any = with_rule(target, rule(LinksFrom::Any));
    let effect = |pdp: &Pdp, p, from, to| link_verdict(pdp, &link(&user(p), from, to)).effect;
    // From p1, under the same team.
    assert_eq!(effect(&team, MEMBER, 1, 2), Effect::Allow);
    assert_eq!(effect(&nobody, MEMBER, 1, 2), Effect::Deny);
    assert_eq!(effect(&any, MEMBER, 1, 2), Effect::Allow);
    // Inside the scope, nothing is crossed.
    assert_eq!(effect(&nobody, MEMBER, 2, 2), Effect::Allow);
    // From another team.
    assert_eq!(effect(&team, DANA, 4, 2), Effect::Deny);
    assert_eq!(effect(&nobody, DANA, 4, 2), Effect::Deny);
    assert_eq!(effect(&any, DANA, 4, 2), Effect::Allow);
}

#[test]
fn tm05_a_link_stays_in_its_tenant() {
    let mut d = data();
    d.orgs.insert(org_id(2));
    let pdp = pdp(d);
    let mut r = link(&user(DANA), 1, 2);
    r.new_links[0].path = vec![project(2), PathEntry::org(&org_id(3)).unwrap()];
    assert_eq!(link_verdict(&pdp, &r).reason.code(), "tenant_mismatch");
    r.new_links[0].path = vec![project(2), PathEntry::org(&org_id(2)).unwrap()];
    assert_eq!(link_verdict(&pdp, &r).reason.code(), "boundary_rule");
}

#[test]
fn a_write_may_be_only_a_move_or_only_a_link_and_not_nothing() {
    let pdp = pdp(data());
    let mut r = mv(&user(DANA), 1, 2);
    r.new_path = None;
    assert!(matches!(
        pdp.write_check(&r),
        Err(PdpError::InvalidInput { .. })
    ));
}

// ---------- Properties ----------

/// A move the world allows by its `parent` rules: a node or a row, under a
/// node or a row outside its own subtree, with no path past the limit.
/// Scopes of type `box` hold rows the model cannot see (ADR-0025), so they
/// stay where they are.
fn pick_move(rng: &mut Rng, t: &Tenant) -> Option<(usize, Vec<PathEntry>)> {
    for _ in 0..20 {
        let i = rng.below(t.nodes.len());
        let n = t.nodes.get(i)?;
        let ty = n.entry.type_name.as_str();
        if ty == "box" || n.path.len() > crate::MAX_PATH {
            continue;
        }
        let parents: Vec<&Node> = t
            .nodes
            .iter()
            .filter(|c| {
                let pt = c.entry.type_name.as_str();
                (pt == "node" || (pt == "doc" && ty == "doc"))
                    && c.entry != n.entry
                    && !c.path.contains(&n.entry)
            })
            .collect();
        if parents.is_empty() {
            continue;
        }
        let parent = rng.pick(&parents);
        let mut path = vec![parent.entry.clone()];
        path.extend(parent.path.iter().cloned());
        let deepest = t
            .nodes
            .iter()
            .filter(|c| c.path.contains(&n.entry))
            .filter_map(|c| c.path.iter().position(|e| *e == n.entry))
            .max()
            .map_or(0, |p| p + 1);
        if path.len() + deepest > crate::MAX_PATH || path == n.path {
            continue;
        }
        return Some((i, path));
    }
    None
}

/// The tree after the move: the node and everything below it get new paths.
fn moved_nodes(t: &Tenant, i: usize, new_path: &[PathEntry]) -> Vec<Node> {
    let this = &t.nodes[i].entry;
    t.nodes
        .iter()
        .map(|n| {
            let mut n = n.clone();
            if n.entry == *this {
                n.path = new_path.to_vec();
            } else if let Some(pos) = n.path.iter().position(|e| e == this) {
                n.path.truncate(pos + 1);
                n.path.extend(new_path.iter().cloned());
            }
            n
        })
        .collect()
}

fn random_rule(rng: &mut Rng) -> BoundaryRule {
    let mv = |rng: &mut Rng| match rng.below(5) {
        0 => Some(MoveRule::Nobody),
        1 => Some(MoveRule::Owners),
        2 => Some(MoveRule::Members),
        _ => None,
    };
    BoundaryRule {
        moves_out: mv(rng),
        moves_in: mv(rng),
        on_looser: match rng.below(3) {
            0 => Some(OnLooser::Block),
            1 => Some(OnLooser::Approve),
            _ => None,
        },
        links_from: match rng.below(4) {
            0 => Some(LinksFrom::Nobody),
            1 => Some(LinksFrom::Team),
            2 => Some(LinksFrom::Any),
            _ => None,
        },
    }
}

/// More assignments than a plain world has: user 1 owns the org, user 2 is
/// a member of it, and others sit on single scopes.
pub(crate) fn with_more_bindings(rng: &mut Rng, w: &mut World) {
    let mut roles: Vec<String> = w.spec.roles.iter().map(|r| r.key.clone()).collect();
    roles.extend(["member".to_owned(), "viewer".to_owned()]);
    for (n, t) in (1..).zip(&mut w.tenants) {
        let org = PathEntry::org(&org_id(n)).unwrap();
        let free = |t: &Tenant, p: &Principal, s: &PathEntry| {
            !t.data
                .bindings
                .iter()
                .any(|b| b.scope == *s && b.subject == direct(p))
        };
        let add = |t: &mut Tenant, p: Principal, role: &str, s: PathEntry, i: usize| {
            if free(t, &p, &s) {
                let id = format!("ra_x{i}");
                t.data.bindings.push(binding(&id, direct(&p), role, s));
            }
        };
        add(t, user(1), "owner", org.clone(), 0);
        add(t, user(2), "member", org, 1);
        let scopes: Vec<PathEntry> = t
            .nodes
            .iter()
            .filter(|n| n.path.len() <= crate::MAX_PATH)
            .map(|n| n.entry.clone())
            .collect();
        for i in 2..12 {
            let p = rng.pick(&principals()[2..]).clone();
            let role = rng.pick(&roles).clone();
            let s = rng.pick(&scopes).clone();
            add(t, p, &role, s, i);
        }
    }
}

/// Boundary rules on a quarter of the scopes, and the assignments of
/// [`with_more_bindings`], so that many moves get past the first checks.
fn with_rules(rng: &mut Rng, w: &mut World) {
    with_more_bindings(rng, w);
    for t in &mut w.tenants {
        for n in &t.nodes {
            if n.path.len() <= crate::MAX_PATH && rng.chance(25) {
                t.data.boundaries.insert(n.entry.clone(), random_rule(rng));
            }
        }
    }
}

fn gained(before: &Decision, after: &Decision) -> bool {
    let sub = |a: &[FieldName], b: &[FieldName]| a.iter().all(|f| b.contains(f));
    after.level > before.level
        || !sub(after.field_mask.read(), before.field_mask.read())
        || !sub(after.field_mask.write(), before.field_mask.write())
        || (after.is_allowed() && !before.is_allowed())
}

/// `true` if `check` gives some principal more after the move, on the moved
/// item or on anything below it.
fn really_widens(pdp: &Pdp, w: &World, t: &Tenant, after: &[Node], this: &PathEntry) -> bool {
    let actions = w.spec.actions();
    principals().iter().any(|p| {
        t.nodes.iter().zip(after).any(|(old, new)| {
            if old.entry != *this && !old.path.contains(this) {
                return false;
            }
            let ty = old.entry.type_name.as_str();
            let list: Vec<String> = if ty == "doc" {
                actions.clone()
            } else {
                vec![format!("{ty}:read"), format!("{ty}:write")]
            };
            list.iter().any(|a| {
                let d0 = pdp.check(&check_req(t, p, &[], a, old));
                let d1 = pdp.check(&check_req(t, p, &[], a, new));
                matches!((d0, d1), (Ok(d0), Ok(d1)) if gained(&d0, &d1))
            })
        })
    })
}

/// What the rules say, written apart from the code: a scope that lets
/// nothing cross, and the comparison of `check` before and after.
fn no_move_widens_past_the_rules(seed: u64, stats: &mut Stats) {
    let mut w = world(seed);
    let mut rng = Rng::new(seed ^ 0x6d6f_7665);
    with_rules(&mut rng, &mut w);
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    for t in &w.tenants {
        let Some((i, new_path)) = pick_move(&mut rng, t) else {
            continue;
        };
        let node = &t.nodes[i];
        let after = moved_nodes(t, i, &new_path);
        let widens = really_widens(&pdp, &w, t, &after, &node.entry);
        stats.moves += 1;
        stats.widening += usize::from(widens);
        let shared = node
            .path
            .iter()
            .rev()
            .zip(new_path.iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let left = &node.path[..node.path.len() - shared];
        let entered = &new_path[..new_path.len() - shared];
        let nobody = left
            .iter()
            .any(|s| t.data.boundaries.get(s).and_then(|r| r.moves_out) == Some(MoveRule::Nobody))
            || entered.iter().any(|s| {
                t.data.boundaries.get(s).and_then(|r| r.moves_in) == Some(MoveRule::Nobody)
            });
        let blocked = left
            .iter()
            .chain(node.path.first().filter(|_| left.is_empty()))
            .any(|s| t.data.boundaries.get(s).and_then(|r| r.on_looser) == Some(OnLooser::Block));
        for (p, actors) in askers() {
            let r = WriteCheckRequest {
                tenant: t.key.clone(),
                subject: p.clone(),
                actors: actors.clone(),
                resource: node.resource(),
                new_attrs: Attrs::new(),
                new_path: Some(new_path.clone()),
                new_links: vec![],
                approved_by: vec![],
                at_least_revision: None,
            };
            let d = pdp
                .write_check(&r)
                .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
            let m = d.moved.unwrap();
            let ctx = format!(
                "seed {seed}: {p} {actors:?} moves {} from {:?} to {new_path:?}: {m:?}",
                node.entry, node.path
            );
            let may_move = m.outcome == MoveOutcome::Allowed;
            assert_eq!(d.effect == Effect::Allow, may_move, "{ctx}");
            if nobody {
                assert!(!may_move, "a scope lets nothing cross: {ctx}");
            }
            if widens && may_move {
                assert!(m.looser, "the move widens and the verdict missed it: {ctx}");
                assert!(!blocked, "blocked: {ctx}");
                // Only the source's owner lets a widening move through.
                assert!(actors.is_empty(), "{ctx}");
                stats.approved += 1;
            }
            if may_move {
                stats.allowed += 1;
                if !m.looser {
                    stats.quiet += 1;
                }
            }
        }
    }
}

#[derive(Default, Debug)]
struct Stats {
    moves: usize,
    widening: usize,
    allowed: usize,
    quiet: usize,
    approved: usize,
    links: usize,
    link_allows: usize,
}

/// A link: allowed only when the source may be written, the target read, and
/// the target's rules take a link from here. It never needs anything else.
fn links_follow_their_rules(seed: u64, stats: &mut Stats) {
    let mut w = world(seed);
    let mut rng = Rng::new(seed ^ 0x6c69_6e6b);
    with_rules(&mut rng, &mut w);
    let pdp = pdp_of(&w.model, &w.tenants.iter().collect::<Vec<_>>());
    for t in &w.tenants {
        let rows: Vec<&Node> = t
            .rows()
            .filter(|r| r.path.len() <= crate::MAX_PATH)
            .collect();
        if rows.len() < 2 {
            continue;
        }
        for _ in 0..4 {
            let (src, dst) = (*rng.pick(&rows), *rng.pick(&rows));
            for (p, actors) in askers() {
                let r = WriteCheckRequest {
                    tenant: t.key.clone(),
                    subject: p.clone(),
                    actors: actors.clone(),
                    resource: src.resource(),
                    new_attrs: Attrs::new(),
                    new_path: None,
                    new_links: vec![dst.resource()],
                    approved_by: vec![],
                    at_least_revision: None,
                };
                let v = pdp.write_check(&r).unwrap().links.pop().unwrap();
                stats.links += 1;
                let may = |action: &str, row: &Node| {
                    pdp.check(&check_req(t, &p, &actors, action, row))
                        .is_ok_and(|d| d.is_allowed())
                };
                let chain: BTreeSet<&PathEntry> =
                    core::iter::once(&src.entry).chain(&src.path).collect();
                let nodes: Vec<&PathEntry> =
                    core::iter::once(&dst.entry).chain(&dst.path).collect();
                let mut rules_pass = true;
                for (i, n) in nodes.iter().enumerate() {
                    if chain.contains(*n) || n.is_org() {
                        break;
                    }
                    match t.data.boundaries.get(*n).and_then(|b| b.links_from) {
                        Some(LinksFrom::Nobody) => rules_pass = false,
                        Some(LinksFrom::Team) => {
                            rules_pass &= chain.contains(nodes[i + 1]);
                        }
                        _ => {}
                    }
                }
                let expected = may("doc:write", src) && may("doc:read", dst) && rules_pass;
                assert_eq!(
                    v.effect == Effect::Allow,
                    expected,
                    "seed {seed}: {p} {actors:?} links {} to {}: {v:?}",
                    src.entry,
                    dst.entry
                );
                stats.link_allows += usize::from(expected);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn tm08_no_move_widens_past_the_rules(seed in any::<u64>()) {
        no_move_widens_past_the_rules(seed, &mut Stats::default());
    }

    #[test]
    fn tm09_links_follow_their_rules(seed in any::<u64>()) {
        links_follow_their_rules(seed, &mut Stats::default());
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 12, ..ProptestConfig::default() })]

    /// A move changes the paths and nothing else, so `list_filter` must keep
    /// its promise on the moved tree.
    #[test]
    fn tm10_list_filter_equals_check_after_a_move(seed in any::<u64>()) {
        let mut w = world(seed);
        let mut rng = Rng::new(seed ^ 0x7061_7468);
        for t in &mut w.tenants {
            if let Some((i, path)) = pick_move(&mut rng, t) {
                t.nodes = moved_nodes(t, i, &path);
            }
        }
        differential(seed, &w, &mut Seen::default());
    }
}

/// The property tests must meet every case, or they prove nothing.
#[test]
fn tm08_the_move_tests_compare_enough() {
    let mut s = Stats::default();
    for seed in 1..=60 {
        no_move_widens_past_the_rules(seed, &mut s);
        links_follow_their_rules(seed, &mut s);
    }
    assert!(s.moves > 80, "{s:?}");
    assert!(s.widening > 20, "{s:?}");
    assert!(s.allowed > 60, "{s:?}");
    assert!(s.quiet > 20, "{s:?}");
    assert!(s.approved > 5, "{s:?}");
    assert!(s.link_allows > 50, "{s:?}");
    assert!(s.links > 500, "{s:?}");
}

/// A moved scope keeps its rows: the old parent stops counting at once
/// (PERMISSION-MODEL.md 10.5).
#[test]
fn access_through_the_old_parent_ends_after_a_move() {
    let pdp = pdp(data());
    let read = |p: u32, path| {
        pdp.check(&crate::CheckRequest {
            tenant: tenant(1),
            subject: user(p),
            actors: vec![],
            action: ActionKey::parse("issue:read").unwrap(),
            resource: issue(path),
            fields: None,
            at_least_revision: None,
        })
        .unwrap()
        .effect
    };
    assert_eq!(read(OWNER1, under(1)), Effect::Allow);
    assert_eq!(read(OWNER1, under(2)), Effect::Deny);
    assert_eq!(read(LEAD, under(1)), Effect::Deny);
    assert_eq!(read(LEAD, under(2)), Effect::Allow);
}
