//! `check`, `batch` and `write_check` on the worked example of
//! PERMISSION-MODEL.md section 17, plus one test per rule the evaluator
//! must keep (ADR-0012, ADR-0013).

use std::collections::BTreeSet;
use std::sync::Arc;

use tutela_contracts::decision::{Effect, Obligation, ReasonCode, RuleId};
use tutela_contracts::keys::{ActionKey, FieldKey, FieldName, Label, ResourceId, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::{Issuer, OrgId, TenantKey};

use crate::model::{GroupKey, Model, RoleKey};
use crate::{
    AttrValue, Attrs, Binding, CheckRequest, Group, LoadError, Member, PathEntry, Pdp, PdpError,
    ResourceRef, ScopeFieldRule, Subject, TenantData, WriteCheckRequest,
};

/// The Kestrel Foods contract tracker (PERMISSION-MODEL.md section 17).
pub(crate) const KESTREL: &str = r#"
version = 1

[app]
name = "contracts"

[types.department]
parent    = "org"
container = true

[types.matter]
parent    = "department"
container = true
starts    = "private"

[types.contract]
parent    = "matter"
container = true
features  = ["chat", "files", "ai"]

[types.contract.fields]
title        = { sensitivity = "internal" }
counterparty = { sensitivity = "internal" }
status       = { sensitivity = "internal" }
review_notes = { sensitivity = "internal" }
assignee     = { sensitivity = "internal", type = "principal", grants_access = true }
budget       = { sensitivity = "confidential", type = "integer" }
labels       = { sensitivity = "internal", type = "string_list", grants_access = true }

[types.contract.actions]
approve = { needs = "write" }
seal    = { needs = "owner" }

[types.invoice]
parent = "contract"

[types.invoice.fields]
number = { sensitivity = "internal" }
amount = { sensitivity = "confidential", type = "integer" }

[roles.viewer]
grants = { department = "read", matter = "read", contract = "read", invoice = "read", "contract.@chat" = "read", "contract.@ai" = "write" }

[roles.legal_reviewer]
grants = { matter = "read", contract = "write", invoice = "read", "contract.title" = "read", "contract.counterparty" = "read", "contract.assignee" = "read", "contract.@chat" = "write", "contract.@ai" = "write", "contract:approve" = true }
assignable_to = ["user", "group"]

[roles.agent]
grants = { matter = "read", contract = "write", invoice = "read" }

[roles.approver]
grants = { contract = "read", "contract:approve" = true }
assignable_to = ["user", "group"]

[roles.editor]
grants = { contract = "write" }
assignable_to = ["user", "group"]

[roles.open_reader]
grants = { contract = "write" }
assignable_to = ["user", "group"]

[[conditions]]
role = "agent"
type = "contract"
when = { is_principal = "assignee" }
else = "read"

[[conditions]]
role = "open_reader"
type = "contract"
when = { not = { in_group = "no_such_group" } }
else = "none"
"#;

pub(crate) fn ty(s: &str) -> ResourceType {
    ResourceType::parse(s).unwrap()
}
pub(crate) fn rid(s: &str) -> ResourceId {
    ResourceId::parse(s).unwrap()
}
pub(crate) fn fname(s: &str) -> FieldName {
    FieldName::parse(s).unwrap()
}
pub(crate) fn action(s: &str) -> ActionKey {
    ActionKey::parse(s).unwrap()
}
pub(crate) fn entry(t: &str, id: &str) -> PathEntry {
    PathEntry::new(ty(t), rid(id))
}
pub(crate) fn user(n: u32) -> Principal {
    format!("user:usr_0193a1b2-c3d4-7a11-8b22-{n:012x}")
        .parse()
        .unwrap()
}
pub(crate) fn agent(n: u32) -> Principal {
    format!("agent:agt_0193a1b2-c3d4-7b33-9c44-{n:012x}")
        .parse()
        .unwrap()
}
pub(crate) fn org_id(n: u32) -> OrgId {
    format!("org_0193a1b2-c3d4-7f00-9a00-{n:012x}")
        .parse()
        .unwrap()
}
pub(crate) fn tenant(n: u32) -> TenantKey {
    TenantKey::new(
        Issuer::parse("https://auth.kestrel.test").unwrap(),
        format!("ten_0193a1b2-c3d4-7e5f-8a6b-{n:012x}")
            .parse()
            .unwrap(),
    )
}
pub(crate) fn rule(s: &str) -> RuleId {
    RuleId::parse(s).unwrap()
}
pub(crate) fn binding(id: &str, subject: Subject, role: &str, scope: PathEntry) -> Binding {
    Binding {
        id: rule(id),
        subject,
        role: RoleKey::parse(role).unwrap(),
        scope,
    }
}
pub(crate) fn direct(p: &Principal) -> Subject {
    Subject::Principal(p.clone())
}

pub(crate) const DANA: u32 = 0xd01;
pub(crate) const OMAR: u32 = 0x002;
pub(crate) const MINA: u32 = 0x003;
pub(crate) const JAE: u32 = 0x004;
pub(crate) const CLAUSE: u32 = 0xc05;

/// The org of the worked example.
pub(crate) fn org() -> PathEntry {
    PathEntry::org(&org_id(1)).unwrap()
}
pub(crate) fn proc() -> PathEntry {
    entry("department", "d-procurement")
}
pub(crate) fn sup() -> PathEntry {
    entry("matter", "m-supplier-renewals")
}
pub(crate) fn price() -> PathEntry {
    entry("matter", "m-price-negotiations")
}
pub(crate) fn board() -> PathEntry {
    entry("matter", "m-board-pricing")
}

/// The tree of the worked example: (resource, its ancestors).
pub(crate) fn path_of(scope: &PathEntry) -> Vec<PathEntry> {
    match (scope.type_name.as_str(), scope.id.as_str()) {
        ("org", _) => vec![],
        ("department", _) => vec![org()],
        ("matter", _) => vec![proc(), org()],
        ("contract", "c-204" | "c-207") => vec![sup(), proc(), org()],
        ("contract", "c-219") => vec![price(), proc(), org()],
        ("contract", "c-311") => vec![board(), proc(), org()],
        ("invoice", "inv-881") => vec![entry("contract", "c-204"), sup(), proc(), org()],
        _ => panic!("not in the worked example: {scope}"),
    }
}

pub(crate) fn kestrel_data() -> TenantData {
    let fr = |id: &str, role: &str, max| ScopeFieldRule {
        id: rule(id),
        scope: sup(),
        field: FieldKey::parse("contract.budget").unwrap(),
        role: Some(RoleKey::parse(role).unwrap()),
        max,
    };
    TenantData {
        orgs: [org_id(1)].into(),
        bindings: vec![
            binding("ra_dana", direct(&user(DANA)), "owner", org()),
            binding("ra_omar_proc", direct(&user(OMAR)), "owner", proc()),
            binding("ra_jae_proc", direct(&user(JAE)), "member", proc()),
            binding("ra_omar_sup", direct(&user(OMAR)), "owner", sup()),
            binding("ra_mina_sup", direct(&user(MINA)), "legal_reviewer", sup()),
            binding("ra_jae_sup", direct(&user(JAE)), "viewer", sup()),
            binding("ra_clause_sup", direct(&agent(CLAUSE)), "agent", sup()),
            binding("ra_dana_board", direct(&user(DANA)), "owner", board()),
        ],
        groups: vec![],
        private_scopes: [sup(), board()].into(),
        field_rules: vec![
            fr("fr_3", "owner", Level::Full),
            fr("fr_4", "agent", Level::Read),
        ],
        ..TenantData::default()
    }
}

pub(crate) fn pdp_with(data: TenantData) -> Pdp {
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(tenant(1), 42, model, data).unwrap();
    pdp
}

pub(crate) fn kestrel() -> Pdp {
    pdp_with(kestrel_data())
}

/// The values of the fields that decide access (`assignee`, `labels`):
/// always sent, `null` when there is none.
fn attrs(assignee: Option<&Principal>) -> Attrs {
    let mut a = Attrs::new();
    let assignee = assignee.map_or(AttrValue::Null, |p| AttrValue::String(p.to_string()));
    a.insert(fname("assignee"), assignee);
    a.insert(fname("labels"), AttrValue::Null);
    a
}

/// A resource with no assignee, at `path_of` its own id.
pub(crate) fn resource_of(t: &str, id: &str) -> ResourceRef {
    resource(t, id, None)
}

fn resource(t: &str, id: &str, assignee: Option<&Principal>) -> ResourceRef {
    let this = entry(t, id);
    ResourceRef {
        type_name: ty(t),
        id: rid(id),
        path: path_of(&this),
        attrs: attrs(assignee),
    }
}

pub(crate) fn c204() -> ResourceRef {
    resource("contract", "c-204", Some(&agent(CLAUSE)))
}

pub(crate) fn req(p: &Principal, act: &str, res: ResourceRef) -> CheckRequest {
    CheckRequest {
        tenant: tenant(1),
        subject: p.clone(),
        actors: vec![],
        action: action(act),
        resource: res,
        fields: None,
        at_least_revision: None,
    }
}

pub(crate) fn delegated(p: &Principal, a: &Principal, act: &str, res: ResourceRef) -> CheckRequest {
    CheckRequest {
        actors: vec![a.clone()],
        ..req(p, act, res)
    }
}

const DATA_FIELDS: [&str; 6] = [
    "assignee",
    "budget",
    "counterparty",
    "review_notes",
    "status",
    "title",
];

fn names(v: &[FieldName]) -> Vec<&str> {
    v.iter().map(FieldName::as_str).collect()
}

/// A value of the declared type of a contract field.
fn value_for(field: &str) -> AttrValue {
    match field {
        "budget" => AttrValue::Integer(1),
        "assignee" => AttrValue::String(user(0x42).to_string()),
        "labels" => AttrValue::Strings(vec!["x".into()]),
        _ => AttrValue::String("x".into()),
    }
}

fn write_req(p: &Principal, actors: Vec<Principal>, field: &str) -> WriteCheckRequest {
    let mut new_attrs = Attrs::new();
    new_attrs.insert(fname(field), value_for(field));
    WriteCheckRequest {
        tenant: tenant(1),
        subject: p.clone(),
        actors,
        resource: c204(),
        new_attrs,
        new_path: None,
        new_links: vec![],
        approved_by: vec![],
        at_least_revision: None,
    }
}

// ---------- 17.2: Mina opens C-204 ----------

#[test]
fn mina_reads_c204_without_the_budget() {
    let pdp = kestrel();
    let mut r = req(&user(MINA), "contract:read", c204());
    r.fields = Some(DATA_FIELDS.map(fname).to_vec());
    let d = pdp.check(&r).unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.level, Level::Write);
    assert_eq!(
        names(d.field_mask.read()),
        [
            "assignee",
            "counterparty",
            "review_notes",
            "status",
            "title"
        ]
    );
    assert_eq!(names(d.field_mask.write()), ["review_notes", "status"]);
    assert_eq!(d.reason.code(), "allowed");
    assert_eq!(d.rev, 42);
    assert!(d.rule_ids.contains(&rule("ra_mina_sup")));
    // FR-1 (the implicit org-root rule on budget) decided the budget.
    assert!(
        d.rule_ids
            .iter()
            .any(|r| r.as_str().starts_with("model:field_rule:"))
    );
    assert_eq!(
        d.obligations,
        [Obligation::Label {
            value: Label::INTERNAL
        }]
    );
    d.check().unwrap();
}

#[test]
fn mina_may_approve_and_sees_every_feature() {
    let pdp = kestrel();
    let d = pdp
        .check(&req(&user(MINA), "contract:approve", c204()))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    let read = names(d.field_mask.read());
    assert!(read.contains(&"@ai") && read.contains(&"@chat") && read.contains(&"@files"));
    assert!(!read.contains(&"budget"));
}

#[test]
fn mina_may_not_write_the_budget() {
    let pdp = kestrel();
    let d = pdp
        .write_check(&write_req(&user(MINA), vec![], "budget"))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.fields.len(), 1);
    assert_eq!(d.fields[0].field.as_str(), "budget");
    assert_eq!(d.fields[0].needs, action("contract:write"));
    assert_eq!(d.fields[0].reason.code(), "level_too_low");
    let ok = pdp
        .write_check(&write_req(&user(MINA), vec![], "review_notes"))
        .unwrap();
    assert_eq!(ok.effect, Effect::Allow);
}

// ---------- 17.4 and 17.5: Clause AI for Jae, for Omar ----------

#[test]
fn tm03_clause_for_jae_gets_the_overlap() {
    let pdp = kestrel();
    let mut r = delegated(&user(JAE), &agent(CLAUSE), "contract:read", c204());
    r.fields = Some(DATA_FIELDS.map(fname).to_vec());
    let d = pdp.check(&r).unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.level, Level::Read);
    assert_eq!(
        names(d.field_mask.read()),
        [
            "assignee",
            "counterparty",
            "review_notes",
            "status",
            "title"
        ]
    );
    assert!(d.field_mask.write().is_empty());
    assert!(d.rule_ids.contains(&rule("ra_jae_sup")));
    assert!(d.rule_ids.contains(&rule("ra_clause_sup")));
    assert!(d.rule_ids.contains(&rule("fr_4")));
    assert_eq!(
        d.obligations,
        [
            Obligation::Audit {
                on_behalf_of: Some(user(JAE)),
                reason_required: false
            },
            Obligation::Label {
                value: Label::INTERNAL
            }
        ]
    );
}

#[test]
fn jae_may_ask_the_ai_on_a_read_item() {
    let pdp = kestrel();
    let d = pdp
        .check(&req(&user(JAE), "contract:read", c204()))
        .unwrap();
    assert_eq!(d.level, Level::Read);
    assert!(d.field_mask.can_write(&fname("@ai")));
    assert!(!d.field_mask.can_write(&fname("@chat")));
}

#[test]
fn tm03_a_task_from_jae_cannot_write_review_notes() {
    let pdp = kestrel();
    let d = pdp
        .write_check(&write_req(&user(JAE), vec![agent(CLAUSE)], "review_notes"))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    // Jae, the person, is the one who lacks the level.
    assert_eq!(d.fields[0].reason.code(), "level_too_low");
}

#[test]
fn a_task_from_omar_may_write_review_notes_and_read_the_budget() {
    let pdp = kestrel();
    let d = pdp
        .write_check(&write_req(&user(OMAR), vec![agent(CLAUSE)], "review_notes"))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    let mut r = delegated(&user(OMAR), &agent(CLAUSE), "contract:read", c204());
    r.fields = Some(vec![fname("budget")]);
    let c = pdp.check(&r).unwrap();
    assert_eq!(names(c.field_mask.read()), ["budget"]);
    assert!(c.field_mask.write().is_empty());
    assert!(c.obligations.contains(&Obligation::Label {
        value: Label::CONFIDENTIAL
    }));
}

#[test]
fn the_agent_condition_narrows_when_not_assigned() {
    let pdp = kestrel();
    let c207 = resource("contract", "c-207", Some(&user(MINA)));
    let d = pdp
        .check(&req(&agent(CLAUSE), "contract:write", c207))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::Read);
    assert_eq!(d.reason.code(), "condition_failed");
    assert!(d.rule_ids.contains(&rule("model:condition:0")));
    // A null assignee: the comparison is false.
    let none = resource("contract", "c-207", None);
    let d = pdp
        .check(&req(&agent(CLAUSE), "contract:write", none))
        .unwrap();
    assert_eq!(d.reason.code(), "condition_failed");
}

// ---------- Org owner, private scopes, agents ----------

#[test]
fn the_org_owner_has_full_inside_private_scopes() {
    let pdp = kestrel();
    let d = pdp
        .check(&req(&user(DANA), "contract:delete", c204()))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.level, Level::Full);
    assert!(d.reason.as_str().contains("org owner"));
}

#[test]
fn a_private_scope_stops_inheritance() {
    let pdp = kestrel();
    let c311 = resource("contract", "c-311", None);
    let d = pdp.check(&req(&user(JAE), "contract:read", c311)).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::None);
    assert!(d.field_mask.is_empty());
    assert_eq!(d.reason.code(), "private_scope");
    // An open matter inherits from the department.
    let c219 = resource("contract", "c-219", None);
    let d = pdp
        .check(&req(&user(JAE), "contract:delete", c219))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
}

#[test]
fn no_role_is_a_default_deny() {
    let pdp = kestrel();
    let c219 = resource("contract", "c-219", None);
    let d = pdp
        .check(&req(&user(0x999), "contract:read", c219))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "no_role");
    assert!(d.rule_ids.is_empty());
}

#[test]
fn agents_never_get_admin_keys_or_owner_only_actions() {
    let mut data = kestrel_data();
    // A stale binding that gives an agent the owner role: never honoured.
    data.bindings
        .push(binding("ra_bad", direct(&agent(CLAUSE)), "owner", proc()));
    let pdp = pdp_with(data);
    for act in [
        "contract:manage_access",
        "contract:seal",
        "contract:manage_fields",
    ] {
        let d = pdp.check(&req(&agent(CLAUSE), act, c204())).unwrap();
        assert_eq!(d.effect, Effect::Deny, "{act}");
    }
    // On C-219 the stale owner binding at the department is closest: the
    // role may not be given to an agent, so it gives nothing.
    let c219 = resource("contract", "c-219", None);
    let d = pdp
        .check(&req(&agent(CLAUSE), "contract:read", c219))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "no_role");
}

#[test]
fn tm03_admin_keys_and_owner_only_actions_never_go_through_delegation() {
    let pdp = kestrel();
    // Omar holds both as owner of the matter; Clause cannot add them.
    for act in ["contract:manage_access", "contract:seal"] {
        let alone = pdp.check(&req(&user(OMAR), act, c204())).unwrap();
        assert_eq!(alone.effect, Effect::Allow, "{act}");
        let d = pdp
            .check(&delegated(&user(OMAR), &agent(CLAUSE), act, c204()))
            .unwrap();
        assert_eq!(d.effect, Effect::Deny, "{act}");
        assert_eq!(d.reason.code(), "admin_only");
    }
}

#[test]
fn an_agent_assigned_at_the_org_root_is_outside_its_reach() {
    let mut data = kestrel_data();
    data.bindings
        .push(binding("ra_root", direct(&agent(7)), "agent", org()));
    let pdp = pdp_with(data);
    let d = pdp.check(&req(&agent(7), "contract:read", c204())).unwrap();
    // C-204 is in a private matter: the private scope stops it first.
    assert_eq!(d.reason.code(), "private_scope");
    let c219 = resource("contract", "c-219", None);
    let d = pdp.check(&req(&agent(7), "contract:read", c219)).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "outside_ai_reach");
    // Through delegation, the person is allowed and the agent is not.
    let c219 = resource("contract", "c-219", None);
    let d = pdp
        .check(&delegated(&user(JAE), &agent(7), "contract:read", c219))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "outside_ai_reach");
}

#[test]
fn delegation_overlap_names_the_actor() {
    let pdp = kestrel();
    // Omar may delete C-204; Clause may only write it.
    let d = pdp
        .check(&delegated(
            &user(OMAR),
            &agent(CLAUSE),
            "contract:delete",
            c204(),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::Write);
    assert_eq!(d.reason.code(), "delegation_overlap");
}

// ---------- Several deciding roles, gone roles, groups ----------

fn with_groups(extra: Vec<Binding>, groups: Vec<Group>) -> Pdp {
    let mut data = kestrel_data();
    data.bindings.extend(extra);
    data.groups = groups;
    pdp_with(data)
}

fn group(key: &str, members: Vec<Member>) -> Group {
    Group {
        key: GroupKey::parse(key).unwrap(),
        members,
    }
}

fn gsub(key: &str) -> Subject {
    Subject::Group(GroupKey::parse(key).unwrap())
}

#[test]
fn group_roles_combine_component_wise_but_grants_are_never_pooled() {
    let u = user(0x100);
    let pdp = with_groups(
        vec![
            binding("ra_g_approver", gsub("approvers"), "approver", price()),
            binding("ra_g_editor", gsub("editors"), "editor", price()),
        ],
        vec![
            group("approvers", vec![Member::Principal(u.clone())]),
            group("editors", vec![Member::Principal(u.clone())]),
        ],
    );
    let c219 = || resource("contract", "c-219", None);
    let d = pdp.check(&req(&u, "contract:write", c219())).unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.level, Level::Write);
    // One role has the grant (at Read), the other the level (no grant).
    let d = pdp.check(&req(&u, "contract:approve", c219())).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "level_too_low");
    assert!(d.reason.as_str().contains("never pooled"), "{}", d.reason);
    assert!(d.rule_ids.contains(&rule("ra_g_approver")));
    assert!(d.rule_ids.contains(&rule("ra_g_editor")));
}

#[test]
fn a_missing_grant_is_named() {
    let u = user(0x101);
    let pdp = with_groups(
        vec![binding("ra_g_editor", gsub("editors"), "editor", price())],
        vec![group("editors", vec![Member::Principal(u.clone())])],
    );
    let d = pdp
        .check(&req(
            &u,
            "contract:approve",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.reason.code(), "missing_grant");
}

#[test]
fn the_direct_assignment_beats_group_ones_at_one_scope() {
    let u = user(0x102);
    let pdp = with_groups(
        vec![
            binding("ra_direct", direct(&u), "viewer", price()),
            binding("ra_g_editor", gsub("editors"), "editor", price()),
        ],
        vec![group("editors", vec![Member::Principal(u.clone())])],
    );
    let d = pdp
        .check(&req(
            &u,
            "contract:write",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::Read);
    assert_eq!(d.rule_ids.first(), Some(&rule("ra_direct")));
    assert!(!d.rule_ids.contains(&rule("ra_g_editor")));
}

#[test]
fn nested_groups_count() {
    let u = user(0x103);
    let pdp = with_groups(
        vec![binding("ra_g_outer", gsub("outer"), "editor", price())],
        vec![
            group(
                "outer",
                vec![Member::Group(GroupKey::parse("inner").unwrap())],
            ),
            group("inner", vec![Member::Principal(u.clone())]),
        ],
    );
    let d = pdp
        .check(&req(
            &u,
            "contract:write",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
}

#[test]
fn a_gone_role_still_decides_its_scope_and_gives_nothing() {
    // Jae is a Member of the department; a binding to a role the model no
    // longer has sits closer, at the open matter.
    let pdp = with_groups(
        vec![binding("ra_ghost", direct(&user(JAE)), "ghost", price())],
        vec![],
    );
    let d = pdp
        .check(&req(
            &user(JAE),
            "contract:read",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::None);
    assert_eq!(d.reason.code(), "no_role");
    assert!(d.reason.as_str().contains("ra_ghost"));
    assert_eq!(d.rule_ids, [rule("ra_ghost")]);
}

#[test]
fn a_role_that_may_not_be_given_to_the_subject_gives_nothing() {
    // `agent` may only be given to agents.
    let pdp = with_groups(
        vec![binding(
            "ra_wrong_kind",
            direct(&user(JAE)),
            "agent",
            price(),
        )],
        vec![],
    );
    let d = pdp
        .check(&req(
            &user(JAE),
            "contract:read",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), "no_role");
}

#[test]
fn an_unknown_group_makes_the_whole_condition_false_even_under_not() {
    let u = user(0x104);
    let pdp = with_groups(
        vec![binding("ra_open", direct(&u), "open_reader", price())],
        vec![],
    );
    let d = pdp
        .check(&req(
            &u,
            "contract:read",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.level, Level::None);
    assert_eq!(d.reason.code(), "condition_failed");
}

// ---------- write_check ----------

#[test]
fn a_grants_access_field_also_needs_manage_access() {
    let pdp = kestrel();
    // Omar owns the matter: he holds manage_access.
    let d = pdp
        .write_check(&write_req(&user(OMAR), vec![], "assignee"))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.fields[0].needs, action("contract:manage_access"));
    // Mina may write `labels` as a field (Legal reviewer has Write on the
    // item and does not set the field) but holds no manage_access.
    let d = pdp
        .write_check(&write_req(&user(MINA), vec![], "labels"))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.fields[0].reason.code(), "admin_only");
    // Never through delegation.
    let d = pdp
        .write_check(&write_req(&user(OMAR), vec![agent(CLAUSE)], "assignee"))
        .unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.fields[0].reason.code(), "admin_only");
}

#[test]
fn write_check_names_every_field_and_denies_unknown_ones() {
    let pdp = kestrel();
    let mut r = write_req(&user(MINA), vec![], "review_notes");
    r.new_attrs.insert(fname("budget"), AttrValue::Integer(1));
    r.new_attrs.insert(fname("no_such_field"), AttrValue::Null);
    r.new_attrs.insert(fname("@ai"), AttrValue::Null);
    let d = pdp.write_check(&r).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    let got: Vec<(&str, Effect)> = d
        .fields
        .iter()
        .map(|v| (v.field.as_str(), v.effect))
        .collect();
    assert_eq!(
        got,
        [
            ("@ai", Effect::Deny),
            ("budget", Effect::Deny),
            ("no_such_field", Effect::Deny),
            ("review_notes", Effect::Allow)
        ]
    );
    assert_eq!(d.fields[2].reason.code(), "not_allowed");
}

#[test]
fn write_check_refuses_a_bad_new_path_and_an_empty_write() {
    let pdp = kestrel();
    let mut r = write_req(&user(OMAR), vec![], "review_notes");
    r.new_path = Some(vec![]);
    assert!(matches!(
        pdp.write_check(&r),
        Err(PdpError::InvalidInput { .. })
    ));
    r.new_path = None;
    r.new_attrs.clear();
    assert!(matches!(
        pdp.write_check(&r),
        Err(PdpError::InvalidInput { .. })
    ));
}

#[test]
fn a_delegated_field_write_needs_the_agent_too() {
    let pdp = kestrel();
    // Omar may write C-207's notes; Clause is not its assignee (Read).
    let mut r = write_req(&user(OMAR), vec![agent(CLAUSE)], "review_notes");
    r.resource = resource("contract", "c-207", Some(&user(MINA)));
    let d = pdp.write_check(&r).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.fields[0].reason.code(), "delegation_overlap");
}

// ---------- Tenants, revisions, errors ----------

#[test]
fn tm05_a_resource_of_another_tenant_is_denied() {
    let pdp = kestrel();
    let mut res = c204();
    res.path = vec![sup(), proc(), PathEntry::org(&org_id(2)).unwrap()];
    let d = pdp.check(&req(&user(DANA), "contract:read", res)).unwrap();
    assert_eq!(d.effect, Effect::Deny);
    assert_eq!(d.reason.code(), ReasonCode::TenantMismatch.as_str());
    assert!(d.field_mask.is_empty());
    // Another tenant key has no bundle at all.
    let mut r = req(&user(DANA), "contract:read", c204());
    r.tenant = tenant(2);
    assert_eq!(pdp.check(&r), Err(PdpError::NoBundle));
}

#[test]
fn tm13_revisions_only_go_up_and_stale_bundles_fail() {
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(tenant(1), 42, Arc::clone(&model), kestrel_data())
        .unwrap();
    assert_eq!(
        pdp.load(tenant(1), 41, Arc::clone(&model), kestrel_data()),
        Err(LoadError::LowerRevision { have: 42, got: 41 })
    );
    assert_eq!(
        pdp.load(tenant(1), 1 << 53, Arc::clone(&model), kestrel_data()),
        Err(LoadError::RevTooLarge)
    );
    pdp.load(tenant(1), 43, model, kestrel_data()).unwrap();
    let mut r = req(&user(MINA), "contract:read", c204());
    r.at_least_revision = Some(44);
    assert_eq!(
        pdp.check(&r),
        Err(PdpError::StaleBundle {
            have_rev: 43,
            need_rev: 44
        })
    );
    r.at_least_revision = Some(43);
    assert_eq!(pdp.check(&r).unwrap().rev, 43);
}

#[test]
fn bad_requests_are_errors_never_allows() {
    let pdp = kestrel();
    let unknown = req(&user(MINA), "contract:frobnicate", c204());
    assert_eq!(
        pdp.check(&unknown),
        Err(PdpError::UnknownAction(action("contract:frobnicate")))
    );
    let mut wrong_type = req(&user(MINA), "invoice:read", c204());
    assert!(matches!(
        pdp.check(&wrong_type),
        Err(PdpError::InvalidInput { .. })
    ));
    wrong_type.resource.type_name = ty("widget");
    wrong_type.action = action("widget:read");
    assert_eq!(
        pdp.check(&wrong_type),
        Err(PdpError::UnknownType(ty("widget")))
    );
    let mut long = req(&user(MINA), "contract:read", c204());
    long.resource.path = (0..33).map(|i| entry("matter", &format!("m{i}"))).collect();
    assert_eq!(pdp.check(&long), Err(PdpError::PathTooLong));
    let mut no_org = req(&user(MINA), "contract:read", c204());
    no_org.resource.path.pop();
    assert!(matches!(
        pdp.check(&no_org),
        Err(PdpError::InvalidInput { .. })
    ));
    // Delegation rules: a user subject, 1 to 4 agent actors.
    let bad = [
        delegated(&agent(CLAUSE), &agent(CLAUSE), "contract:read", c204()),
        delegated(&user(JAE), &user(MINA), "contract:read", c204()),
        CheckRequest {
            actors: vec![agent(1), agent(2), agent(3), agent(4), agent(5)],
            ..req(&user(JAE), "contract:read", c204())
        },
    ];
    for r in &bad {
        assert!(matches!(pdp.check(r), Err(PdpError::InvalidInput { .. })));
    }
}

#[test]
fn a_batch_answers_in_order_and_fails_as_a_whole() {
    let pdp = kestrel();
    let reqs = vec![
        req(&user(MINA), "contract:read", c204()),
        req(&user(JAE), "contract:write", c204()),
    ];
    let out = pdp.batch(&reqs).unwrap();
    assert_eq!(
        out.iter().map(|d| d.effect).collect::<Vec<_>>(),
        [Effect::Allow, Effect::Deny]
    );
    let mut bad = reqs;
    bad.push(req(&user(MINA), "invoice:read", c204()));
    assert!(matches!(
        pdp.batch(&bad),
        Err(PdpError::InvalidInput { index: Some(2), .. })
    ));
}

#[test]
fn checks_on_the_org_itself_work() {
    let pdp = kestrel();
    let org_res = ResourceRef {
        type_name: ResourceType::ORG,
        id: org().id,
        path: vec![],
        attrs: Attrs::new(),
    };
    let d = pdp
        .check(&req(&user(DANA), "org:manage_access", org_res.clone()))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    let d = pdp.check(&req(&user(JAE), "org:read", org_res)).unwrap();
    assert_eq!(d.effect, Effect::Deny);
}

#[test]
fn load_refuses_broken_data() {
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let load = |data: TenantData| Pdp::new().load(tenant(1), 1, Arc::clone(&model), data);
    let mut dup = kestrel_data();
    dup.bindings
        .push(binding("ra_dup", direct(&user(JAE)), "owner", sup()));
    assert_eq!(load(dup), Err(LoadError::DuplicateBinding(rule("ra_dup"))));
    let mut foreign = kestrel_data();
    foreign.bindings.push(binding(
        "ra_far",
        direct(&user(JAE)),
        "owner",
        PathEntry::org(&org_id(9)).unwrap(),
    ));
    assert!(matches!(load(foreign), Err(LoadError::UnknownOrg(_))));
    let mut unknown_group = kestrel_data();
    unknown_group
        .bindings
        .push(binding("ra_g", gsub("nobody"), "viewer", sup()));
    assert!(matches!(
        load(unknown_group),
        Err(LoadError::UnknownGroup(_))
    ));
    let mut cycle = kestrel_data();
    cycle.groups = vec![
        group("a", vec![Member::Group(GroupKey::parse("b").unwrap())]),
        group("b", vec![Member::Group(GroupKey::parse("a").unwrap())]),
    ];
    assert!(matches!(load(cycle), Err(LoadError::GroupCycle(_))));
    let mut root_rule = kestrel_data();
    root_rule.field_rules[0].scope = org();
    assert_eq!(load(root_rule), Err(LoadError::OrgRootRule(rule("fr_3"))));
}

#[test]
fn every_decision_passes_the_contract_checks() {
    let pdp = kestrel();
    let principals = [
        user(DANA),
        user(OMAR),
        user(MINA),
        user(JAE),
        agent(CLAUSE),
        user(0x999),
    ];
    let acts = [
        "contract:read",
        "contract:write",
        "contract:delete",
        "contract:approve",
        "contract:seal",
        "contract:manage_access",
        "contract:read_audit",
    ];
    let mut seen = BTreeSet::new();
    for p in &principals {
        for a in acts {
            for c in ["c-204", "c-207", "c-219", "c-311"] {
                let d = pdp
                    .check(&req(p, a, resource("contract", c, Some(&agent(CLAUSE)))))
                    .unwrap();
                d.check().unwrap();
                serde_json::to_string(&d).unwrap();
                seen.insert(d.reason.code().to_owned());
            }
        }
    }
    for code in [
        "allowed",
        "no_role",
        "private_scope",
        "level_too_low",
        "missing_grant",
        "admin_only",
    ] {
        assert!(seen.contains(code), "{code} never came up: {seen:?}");
    }
}

// ---------- Review round 1: load guards, request checks, the write mask ----------

#[test]
fn tm05_an_org_belongs_to_one_tenant_only() {
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(tenant(1), 1, Arc::clone(&model), kestrel_data())
        .unwrap();
    // Tenant 2 claims tenant 1's org: refused, tenant 1 untouched.
    let theirs = TenantData {
        orgs: [org_id(1), org_id(2)].into(),
        ..TenantData::default()
    };
    assert_eq!(
        pdp.load(tenant(2), 1, Arc::clone(&model), theirs),
        Err(LoadError::OrgClaimed(org_id(1)))
    );
    assert_eq!(pdp.rev(&tenant(2)), None);
    // Tenant 1 may reload its own org; once it lets the org go, tenant 2
    // may take it.
    pdp.load(tenant(1), 2, Arc::clone(&model), kestrel_data())
        .unwrap();
    let moved = TenantData {
        orgs: [org_id(3)].into(),
        ..TenantData::default()
    };
    pdp.load(tenant(1), 3, Arc::clone(&model), moved).unwrap();
    let now = TenantData {
        orgs: [org_id(1)].into(),
        ..TenantData::default()
    };
    pdp.load(tenant(2), 1, model, now).unwrap();
}

fn chain_of_groups(n: usize) -> Vec<Group> {
    (0..n)
        .map(|i| {
            let members = if i + 1 < n {
                vec![Member::Group(
                    GroupKey::parse(&format!("g{}", i + 1)).unwrap(),
                )]
            } else {
                vec![]
            };
            group(&format!("g{i}"), members)
        })
        .collect()
}

#[test]
fn groups_nested_too_deep_are_refused() {
    use crate::MAX_GROUP_DEPTH;
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let load = |groups: Vec<Group>| {
        let data = TenantData {
            groups,
            ..kestrel_data()
        };
        Pdp::new().load(tenant(1), 1, Arc::clone(&model), data)
    };
    assert_eq!(load(chain_of_groups(MAX_GROUP_DEPTH)), Ok(()));
    assert!(matches!(
        load(chain_of_groups(MAX_GROUP_DEPTH + 1)),
        Err(LoadError::GroupsTooDeep(_))
    ));
}

#[test]
fn a_group_closure_above_the_limit_is_refused() {
    use crate::MAX_GROUP_CLOSURE;
    // 40,000 users in the innermost of 26 nested groups: 1,040,000 pairs.
    let mut groups = chain_of_groups(26);
    let users = MAX_GROUP_CLOSURE / 26 + 1;
    if let Some(inner) = groups.last_mut() {
        inner.members = (0..users)
            .map(|i| Member::Principal(user(0x10_0000 + u32::try_from(i).unwrap())))
            .collect();
    }
    let data = TenantData {
        groups,
        ..kestrel_data()
    };
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    assert_eq!(
        Pdp::new().load(tenant(1), 1, model, data),
        Err(LoadError::GroupClosureTooLarge)
    );
}

#[test]
fn field_values_of_the_wrong_type_are_errors_not_nulls() {
    let pdp = kestrel();
    let mut r = req(&user(MINA), "contract:read", c204());
    r.resource
        .attrs
        .insert(fname("assignee"), AttrValue::Integer(5));
    assert!(matches!(pdp.check(&r), Err(PdpError::InvalidInput { .. })));
    r.resource.attrs.insert(
        fname("assignee"),
        AttrValue::String("not a principal".into()),
    );
    assert!(matches!(pdp.check(&r), Err(PdpError::InvalidInput { .. })));
    r.resource.attrs.insert(fname("assignee"), AttrValue::Null);
    assert!(pdp.check(&r).is_ok());
    // A name the type does not declare is not read and not checked.
    r.resource
        .attrs
        .insert(fname("not_a_field"), AttrValue::Integer(5));
    assert!(pdp.check(&r).is_ok());
    // In a write, too.
    let mut w = write_req(&user(OMAR), vec![], "budget");
    w.new_attrs
        .insert(fname("budget"), AttrValue::String("lots".into()));
    assert!(matches!(
        pdp.write_check(&w),
        Err(PdpError::InvalidInput { .. })
    ));
}

#[test]
fn requests_have_size_bounds() {
    use crate::{MAX_BATCH, MAX_FIELDS};
    let pdp = kestrel();
    let many = vec![req(&user(MINA), "contract:read", c204()); MAX_BATCH + 1];
    assert!(matches!(
        pdp.batch(&many),
        Err(PdpError::InvalidInput { index: None, .. })
    ));
    let mut r = req(&user(MINA), "contract:read", c204());
    r.fields = Some(vec![fname("title"); MAX_FIELDS + 1]);
    assert!(matches!(pdp.check(&r), Err(PdpError::InvalidInput { .. })));
}

#[test]
fn a_path_with_a_repeat_or_the_resource_itself_is_refused() {
    let pdp = kestrel();
    let mut twice = req(&user(MINA), "contract:read", c204());
    twice.resource.path = vec![sup(), sup(), proc(), org()];
    assert!(matches!(
        pdp.check(&twice),
        Err(PdpError::InvalidInput { .. })
    ));
    let mut itself = req(&user(MINA), "contract:read", c204());
    itself.resource.path = vec![entry("contract", "c-204"), sup(), proc(), org()];
    assert!(matches!(
        pdp.check(&itself),
        Err(PdpError::InvalidInput { .. })
    ));
}

#[test]
fn tm03_an_agent_never_sees_a_grants_access_field_as_writable() {
    let pdp = kestrel();
    // Clause is C-204's assignee: Write on the item and on its fields, but
    // `assignee` and `labels` decide access and need `manage_access`.
    let d = pdp
        .check(&req(&agent(CLAUSE), "contract:read", c204()))
        .unwrap();
    assert_eq!(d.level, Level::Write);
    assert!(d.field_mask.can_write(&fname("review_notes")));
    assert!(!d.field_mask.can_write(&fname("assignee")));
    assert!(!d.field_mask.can_write(&fname("labels")));
    assert!(d.field_mask.can_write(&fname("status")));
    assert!(d.field_mask.can_read(&fname("assignee")));
    let w = pdp
        .write_check(&write_req(&agent(CLAUSE), vec![], "assignee"))
        .unwrap();
    assert_eq!(w.effect, Effect::Deny);
    // Omar holds manage_access: alone he may; through Clause he may not.
    let omar = pdp
        .check(&req(&user(OMAR), "contract:read", c204()))
        .unwrap();
    assert!(omar.field_mask.can_write(&fname("assignee")));
    let both = pdp
        .check(&delegated(
            &user(OMAR),
            &agent(CLAUSE),
            "contract:read",
            c204(),
        ))
        .unwrap();
    assert!(!both.field_mask.can_write(&fname("assignee")));
    assert!(both.field_mask.can_write(&fname("review_notes")));
}

#[test]
fn a_group_closure_that_takes_too_much_work_is_refused() {
    // 100 top groups each hold the same 1,000 groups, and 50 users are in
    // all 1,000: only 55,000 pairs, but about 5,000,000 steps to gather.
    let tops: Vec<String> = (0..100).map(|i| format!("t{i}")).collect();
    let bottoms: Vec<String> = (0..1_000).map(|i| format!("b{i}")).collect();
    let users: Vec<Member> = (0..50)
        .map(|i| Member::Principal(user(0x20_0000 + i)))
        .collect();
    let mut groups: Vec<Group> = tops
        .iter()
        .map(|t| {
            let held = bottoms
                .iter()
                .map(|b| Member::Group(GroupKey::parse(b).unwrap()))
                .collect();
            group(t, held)
        })
        .collect();
    groups.extend(bottoms.iter().map(|b| group(b, users.clone())));
    let data = TenantData {
        groups,
        ..kestrel_data()
    };
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    assert_eq!(
        Pdp::new().load(tenant(1), 1, model, data),
        Err(LoadError::GroupClosureTooLarge)
    );
}

/// `levels` levels of `width` groups, each group holding every group of the
/// next level. No principal is in any of them.
fn layered_groups(levels: usize, width: usize) -> Vec<Group> {
    let key = |l: usize, i: usize| format!("l{l}g{i}");
    (0..levels)
        .flat_map(|l| {
            (0..width).map(move |i| {
                let held = if l + 1 < levels {
                    (0..width)
                        .map(|j| Member::Group(GroupKey::parse(&key(l + 1, j)).unwrap()))
                        .collect()
                } else {
                    vec![]
                };
                group(&key(l, i), held)
            })
        })
        .collect()
}

#[test]
fn a_closure_of_groups_alone_that_takes_too_much_work_is_refused() {
    // No principal is in a group, so the budget is spent while the groups'
    // own closures are gathered. At 32 levels of 25 that is about 7,300,000
    // steps; at 16 levels about 1,650,000, under the 4,000,000 limit.
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let load = |groups: Vec<Group>| {
        let data = TenantData {
            groups,
            ..kestrel_data()
        };
        Pdp::new().load(tenant(1), 1, Arc::clone(&model), data)
    };
    assert_eq!(load(layered_groups(16, 25)), Ok(()));
    assert_eq!(
        load(layered_groups(crate::MAX_GROUP_DEPTH, 25)),
        Err(LoadError::GroupClosureTooLarge)
    );
}

#[test]
fn tm05_a_refused_reload_changes_nothing() {
    let model = Arc::new(Model::from_toml(KESTREL).unwrap());
    let mut pdp = Pdp::new();
    pdp.load(tenant(1), 1, Arc::clone(&model), kestrel_data())
        .unwrap();
    let other = TenantData {
        orgs: [org_id(2)].into(),
        ..TenantData::default()
    };
    pdp.load(tenant(2), 1, Arc::clone(&model), other).unwrap();
    let probe = req(&user(MINA), "contract:read", c204());
    let before = pdp.check(&probe).unwrap();

    let cycle = TenantData {
        groups: vec![
            group("a", vec![Member::Group(GroupKey::parse("b").unwrap())]),
            group("b", vec![Member::Group(GroupKey::parse("a").unwrap())]),
        ],
        ..kestrel_data()
    };
    let deep = TenantData {
        groups: chain_of_groups(crate::MAX_GROUP_DEPTH + 1),
        ..kestrel_data()
    };
    let claims_other = TenantData {
        orgs: [org_id(1), org_id(2)].into(),
        ..kestrel_data()
    };
    let closure_too_large = TenantData {
        groups: layered_groups(crate::MAX_GROUP_DEPTH, 25),
        ..kestrel_data()
    };
    for bad in [cycle, deep, claims_other, closure_too_large] {
        assert!(pdp.load(tenant(1), 2, Arc::clone(&model), bad).is_err());
        // The revision, the decisions and the org claims are as before.
        assert_eq!(pdp.rev(&tenant(1)), Some(1));
        assert_eq!(pdp.check(&probe).unwrap(), before);
        let grab = TenantData {
            orgs: [org_id(1)].into(),
            ..TenantData::default()
        };
        assert_eq!(
            pdp.load(tenant(2), 2, Arc::clone(&model), grab),
            Err(LoadError::OrgClaimed(org_id(1)))
        );
    }
}

// ---------- Independent review: missing fields, integers, many group roles ----------

#[test]
fn a_field_that_decides_access_must_be_sent() {
    // Clause's condition reads `assignee`. Left out, it would be read as
    // null, and under `not` a null comparison is true while SQL compares
    // the real column. So a field with `grants_access` must be sent, as
    // `null` when it has no value.
    let pdp = kestrel();
    for field in ["assignee", "labels"] {
        let mut r = req(&agent(CLAUSE), "contract:read", c204());
        r.resource.attrs.remove(&fname(field));
        assert!(
            matches!(pdp.check(&r), Err(PdpError::InvalidInput { .. })),
            "{field}"
        );
        assert!(matches!(
            pdp.batch(std::slice::from_ref(&r)),
            Err(PdpError::InvalidInput { .. })
        ));
        let mut w = write_req(&user(OMAR), vec![], "review_notes");
        w.resource.attrs.remove(&fname(field));
        assert!(matches!(
            pdp.write_check(&w),
            Err(PdpError::InvalidInput { .. })
        ));
    }
    // An explicit null is a value: Clause is then not the assignee.
    let mut r = req(&agent(CLAUSE), "contract:read", c204());
    r.resource.attrs.insert(fname("assignee"), AttrValue::Null);
    assert_eq!(pdp.check(&r).unwrap().level, Level::Read);
    // The changed fields of a write need not repeat the others.
    let w = write_req(&user(OMAR), vec![], "review_notes");
    assert_eq!(w.new_attrs.len(), 1);
    assert_eq!(pdp.write_check(&w).unwrap().effect, Effect::Allow);
}

#[test]
fn a_field_integer_must_fit_every_sdk() {
    let pdp = kestrel();
    let max = i64::try_from(tutela_contracts::encoding::MAX_JSON_INT).unwrap();
    for (v, ok) in [
        (max, true),
        (-max, true),
        (max + 1, false),
        (i64::MIN, false),
    ] {
        let mut w = write_req(&user(OMAR), vec![], "budget");
        w.new_attrs.insert(fname("budget"), AttrValue::Integer(v));
        let got = pdp.write_check(&w);
        assert_eq!(got.is_ok(), ok, "{v}: {got:?}");
        if !ok {
            assert!(matches!(got, Err(PdpError::InvalidInput { .. })));
        }
    }
}

#[test]
fn many_group_roles_at_one_scope_give_each_rule_id_once_in_binding_order() {
    // 3,000 groups hold the user, each with a role at Price negotiations.
    // The user's groups outnumber the group bindings at most scopes, and
    // the other way round at this one: both lookups give the same roles.
    let u = user(0x300);
    let n = 3_000;
    let groups: Vec<Group> = (0..n)
        .map(|i| group(&format!("g{i}"), vec![Member::Principal(u.clone())]))
        .collect();
    let bindings: Vec<Binding> = (0..n)
        .rev()
        .map(|i| {
            binding(
                &format!("ra_g{i:04}"),
                gsub(&format!("g{i}")),
                "viewer",
                price(),
            )
        })
        .collect();
    let want: Vec<RuleId> = bindings.iter().map(|b| b.id.clone()).collect();
    let pdp = with_groups(bindings, groups);
    let d = pdp
        .check(&req(
            &u,
            "contract:read",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    // The deciding assignments first, then the rule that hides `budget`.
    assert_eq!(d.rule_ids.get(..n), Some(want.as_slice()));
    assert_eq!(&d.rule_ids[n..], [rule("model:field_rule:0")]);
    // Few groups, many bindings at the scope: the other lookup.
    let v = user(0x301);
    let mut groups: Vec<Group> = (0..n)
        .map(|i| group(&format!("g{i}"), vec![Member::Principal(u.clone())]))
        .collect();
    if let Some(g) = groups.get_mut(7) {
        g.members.push(Member::Principal(v.clone()));
    }
    let bindings: Vec<Binding> = (0..n)
        .map(|i| {
            binding(
                &format!("ra_g{i:04}"),
                gsub(&format!("g{i}")),
                "viewer",
                price(),
            )
        })
        .collect();
    let pdp = with_groups(bindings, groups);
    let d = pdp
        .check(&req(
            &v,
            "contract:read",
            resource("contract", "c-219", None),
        ))
        .unwrap();
    assert_eq!(d.effect, Effect::Allow);
    assert_eq!(d.rule_ids, [rule("ra_g0007"), rule("model:field_rule:0")]);
}
