//! The walk and the evaluation of one principal on one resource
//! (PERMISSION-MODEL.md 7.1 steps 3 to 6). `check`, `write_check` and
//! `list_filter` all use this code.

use std::collections::BTreeSet;

use tutela_contracts::decision::{Reason, ReasonCode, RuleId};
use tutela_contracts::keys::{ActionKey, ActionRequirement, FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::{Principal, PrincipalKind};

use crate::api::{AttrValue, Attrs, PathEntry, PdpError};
use crate::data::{Binding, Index, ScopeIndex, Subject};
use crate::model::{
    CustomAction, Model, Role, RoleKey, SeededRole, SubjectKind, Template, Value, is_admin_key,
};

/// The model and the tenant data of one loaded bundle.
#[derive(Clone, Copy)]
pub(crate) struct Ctx<'a> {
    pub model: &'a Model,
    pub index: &'a Index,
}

/// What an action needs.
#[derive(Clone, Copy)]
pub(crate) enum ActionKind<'m> {
    /// `read`, `write` or `delete`: a level on the item.
    Level(Level),
    /// A custom action of the type.
    Custom(&'m CustomAction),
    /// An admin key, `manage_access` included: the key only.
    Admin,
}

impl ActionKind<'_> {
    /// Admin keys and owner-only custom actions: never through delegation
    /// and never for agents (PERMISSION-MODEL.md 5.3).
    pub fn owner_only(&self) -> bool {
        match self {
            Self::Admin => true,
            Self::Custom(def) => def.needs == ActionRequirement::OwnerOnly,
            Self::Level(_) => false,
        }
    }
}

/// What the action is, for one type. Unknown actions are an error.
pub(crate) fn action_kind<'m>(
    model: &'m Model,
    action: &ActionKey,
) -> Result<ActionKind<'m>, PdpError> {
    let t = action.resource_type();
    let def = model.types().get(t);
    if def.is_none() && *t != ResourceType::ORG {
        return Err(PdpError::UnknownType(t.clone()));
    }
    if let Some(b) = action.as_builtin() {
        return Ok(match b.requirement() {
            ActionRequirement::Level(l) => ActionKind::Level(l),
            ActionRequirement::OwnerOnly => ActionKind::Admin,
        });
    }
    if is_admin_key(action.action()) {
        return Ok(ActionKind::Admin);
    }
    def.and_then(|d| d.actions.get(action.action()))
        .map(ActionKind::Custom)
        .ok_or_else(|| PdpError::UnknownAction(action.clone()))
}

/// The nodes a walk visits: the resource itself, then its ancestors up to
/// the org, with what the tenant data says about each one.
pub(crate) struct Walk<'r, 'i> {
    pub nodes: Vec<&'r PathEntry>,
    pub scopes: Vec<Option<&'i ScopeIndex>>,
}

impl<'r, 'i> Walk<'r, 'i> {
    /// `this` is the resource itself; `path` its ancestors, nearest first.
    pub fn new(index: &'i Index, this: &'r PathEntry, path: &'r [PathEntry]) -> Self {
        let nodes: Vec<&PathEntry> = core::iter::once(this).chain(path).collect();
        let scopes = nodes.iter().map(|n| index.scopes.get(*n)).collect();
        Self { nodes, scopes }
    }

    /// The org root: the last node.
    pub fn org(&self) -> Option<&'r PathEntry> {
        self.nodes.last().copied()
    }
}

/// Why a principal has the roles it has on a resource.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    /// A node with an assignment was found.
    Found,
    /// No assignment on the path: default deny.
    NoRole,
    /// A private scope (this walk index) stopped inheritance.
    Private(usize),
    /// An agent whose closest assignment is at the org root: `ai_reach` is
    /// never the whole org.
    OutsideReach,
}

/// One deciding role, evaluated on its own (PERMISSION-MODEL.md 6.3).
pub(crate) struct RoleEval<'m> {
    /// The binding that gives it.
    pub binding: usize,
    /// The role; `None` when the model no longer has it or it may not be
    /// given to the binding's subject. Such a role gives nothing.
    pub role: Option<(&'m RoleKey, &'m Role)>,
    /// Its level for the type, before conditions.
    pub base: Level,
    /// Its level after its own conditions.
    pub item: Level,
    /// The model conditions (indexes) that were false.
    pub fired: Vec<usize>,
}

/// One principal's result on one resource (steps 3 and 4).
pub(crate) struct Side<'a, 'm> {
    pub principal: &'a Principal,
    pub outcome: Outcome,
    /// The walk index of the deciding node (`Found` only).
    pub node: usize,
    pub roles: Vec<RoleEval<'m>>,
    pub org_owner: bool,
}

impl Side<'_, '_> {
    /// The item level: the highest of the deciding roles.
    pub fn item(&self) -> Level {
        if self.outcome != Outcome::Found {
            return Level::None;
        }
        self.roles
            .iter()
            .map(|r| r.item)
            .max()
            .unwrap_or(Level::None)
    }

    /// `true` for an agent principal.
    pub fn is_agent(&self) -> bool {
        self.principal.kind() == PrincipalKind::Agent
    }
}

/// The deciding bindings for `p` at one scope (PERMISSION-MODEL.md 6.3):
/// the direct one, else every group one whose group holds `p`, in binding
/// order. Empty when there is none.
pub(crate) fn bindings_at(index: &Index, node: &ScopeIndex, p: &Principal) -> Vec<usize> {
    if let Some(&bi) = node.direct.get(p) {
        return vec![bi];
    }
    let groups = index.groups_of(p);
    // Walk the smaller of the two: the group bindings here, or `p`'s groups.
    let mut out: Vec<usize> = if node.groups.len() <= groups.len() {
        node.groups
            .iter()
            .filter(|(g, _)| groups.contains(*g))
            .map(|(_, &b)| b)
            .collect()
    } else {
        groups
            .iter()
            .filter_map(|g| node.groups.get(g).copied())
            .collect()
    };
    out.sort_unstable();
    out
}

/// The role a binding gives, if the model has it and it may be given to the
/// binding's subject.
pub(crate) fn role_for<'m>(model: &'m Model, b: &Binding) -> Option<(&'m RoleKey, &'m Role)> {
    let (k, r) = model.roles().get_key_value(&b.role)?;
    let kind = match &b.subject {
        Subject::Principal(p) => SubjectKind::Principal(p.kind()),
        Subject::Group(_) => SubjectKind::Group,
    };
    r.assignable_to.contains(&kind).then_some((k, r))
}

/// The binding that makes `p` the org Owner of `org`: a direct `owner`
/// assignment at the org root. People only (PERMISSION-MODEL.md 6.1).
pub(crate) fn org_owner(ctx: Ctx<'_>, org: &PathEntry, p: &Principal) -> Option<usize> {
    if p.kind() != PrincipalKind::User {
        return None;
    }
    let &bi = ctx.index.scopes.get(org)?.direct.get(p)?;
    let b = ctx.index.bindings.get(bi)?;
    (b.role.as_str() == SeededRole::Owner.key() && role_for(ctx.model, b).is_some()).then_some(bi)
}

/// Steps 3 and 4 for one principal: walk up, the closest assignment wins, a
/// private scope stops inheritance, then each role's own conditions narrow
/// it.
pub(crate) fn resolve<'a, 'm>(
    ctx: Ctx<'m>,
    walk: &Walk<'_, '_>,
    ty: &ResourceType,
    attrs: &Attrs,
    p: &'a Principal,
) -> Side<'a, 'm> {
    let mut side = Side {
        principal: p,
        outcome: Outcome::NoRole,
        node: 0,
        roles: Vec::new(),
        org_owner: false,
    };
    let last = walk.nodes.len().saturating_sub(1);
    let mut found: Option<(usize, Vec<usize>)> = None;
    if let Some(bi) = walk.org().and_then(|org| org_owner(ctx, org, p)) {
        found = Some((last, vec![bi]));
        side.org_owner = true;
    } else {
        for (i, scope) in walk.scopes.iter().enumerate() {
            let Some(scope) = scope else { continue };
            let bindings = bindings_at(ctx.index, scope, p);
            if !bindings.is_empty() {
                found = Some((i, bindings));
                break;
            }
            if scope.private {
                side.outcome = Outcome::Private(i);
                return side;
            }
        }
    }
    let Some((node, bindings)) = found else {
        return side;
    };
    side.node = node;
    if p.kind() == PrincipalKind::Agent && node == last {
        side.outcome = Outcome::OutsideReach;
        return side;
    }
    side.outcome = Outcome::Found;
    let p_text = p.to_string();
    let groups = ctx.index.groups_of(p);
    for bi in bindings {
        let role = ctx
            .index
            .bindings
            .get(bi)
            .and_then(|b| role_for(ctx.model, b));
        let mut eval = RoleEval {
            binding: bi,
            role,
            base: Level::None,
            item: Level::None,
            fired: Vec::new(),
        };
        if let Some((key, r)) = role {
            eval.base = r.level(ty);
            eval.item = eval.base;
            for &ci in ctx.index.conditions_of(key, ty) {
                // The index is built from this model, so `ci` is always
                // valid; if not, fail closed.
                let Some(c) = ctx.model.conditions().get(ci) else {
                    eval.item = Level::None;
                    continue;
                };
                if !condition_holds(ctx, &c.when, attrs, &p_text, groups) {
                    eval.item = eval.item.min(c.otherwise);
                    eval.fired.push(ci);
                }
            }
        }
        side.roles.push(eval);
    }
    side
}

/// A model condition on one item. A condition that names a group the tenant
/// does not have is false as a whole, even under `not` (MANIFEST.md 8).
pub(crate) fn condition_holds(
    ctx: Ctx<'_>,
    when: &Template,
    attrs: &Attrs,
    p_text: &str,
    groups: &BTreeSet<usize>,
) -> bool {
    if names_unknown_group(ctx.index, when) {
        return false;
    }
    holds(ctx.index, when, attrs, p_text, groups)
}

/// `true` if the template names a group the tenant does not have.
pub(crate) fn names_unknown_group(index: &Index, t: &Template) -> bool {
    match t {
        Template::InGroup { group } => !index.group_ids.contains_key(group),
        Template::And(v) | Template::Or(v) => v.iter().any(|x| names_unknown_group(index, x)),
        Template::Not(x) => names_unknown_group(index, x),
        Template::Eq { .. }
        | Template::In { .. }
        | Template::Contains { .. }
        | Template::IsPrincipal { .. } => false,
    }
}

/// A template on one item. A comparison with a null or missing field, or
/// with a value of another type, is false.
fn holds(
    index: &Index,
    t: &Template,
    attrs: &Attrs,
    p_text: &str,
    groups: &BTreeSet<usize>,
) -> bool {
    match t {
        Template::Eq { field, value } => attrs.get(field).is_some_and(|a| same(a, value)),
        Template::In { field, values } => attrs
            .get(field)
            .is_some_and(|a| values.iter().any(|v| same(a, v))),
        Template::Contains { field, value } => {
            matches!(attrs.get(field), Some(AttrValue::Strings(v)) if v.contains(value))
        }
        Template::IsPrincipal { field } => {
            matches!(attrs.get(field), Some(AttrValue::String(s)) if s == p_text)
        }
        Template::InGroup { group } => index
            .group_ids
            .get(group)
            .is_some_and(|g| groups.contains(g)),
        Template::And(v) => v.iter().all(|x| holds(index, x, attrs, p_text, groups)),
        Template::Or(v) => v.iter().any(|x| holds(index, x, attrs, p_text, groups)),
        Template::Not(x) => !holds(index, x, attrs, p_text, groups),
    }
}

fn same(a: &AttrValue, v: &Value) -> bool {
    match (a, v) {
        (AttrValue::String(a), Value::String(b)) => a == b,
        (AttrValue::Integer(a), Value::Integer(b)) => a == b,
        (AttrValue::Boolean(a), Value::Boolean(b)) => a == b,
        _ => false,
    }
}

/// A field rule that capped a field.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum RuleRef {
    /// A rule at one scope: an index into the tenant data's rules.
    Scope(usize),
    /// A model rule at the org root: an index into `Model::field_rules`.
    Root(usize),
}

impl RuleRef {
    pub fn id(self, index: &Index) -> Option<RuleId> {
        match self {
            Self::Scope(i) => index.field_rules.get(i).map(|r| r.id.clone()),
            Self::Root(i) => RuleId::parse(&format!("model:field_rule:{i}")).ok(),
        }
    }
}

/// The id of a model condition, for `rule_ids`.
pub(crate) fn condition_id(ci: usize) -> Option<RuleId> {
    RuleId::parse(&format!("model:condition:{ci}")).ok()
}

/// The closest field rule for one role and field: walk up from the item;
/// the first scope with a rule for this role or for all roles wins, a rule
/// for the role first; else the model's org-root rules.
fn closest_cap(
    ctx: Ctx<'_>,
    rule_nodes: &[&ScopeIndex],
    role: &RoleKey,
    field: &FieldKey,
) -> (Level, Option<RuleRef>) {
    for node in rule_nodes {
        if let Some(caps) = node.rules.get(field) {
            if let Some(&(l, ri)) = caps.roles.get(role) {
                return (l, Some(RuleRef::Scope(ri)));
            }
            if let Some((l, ri)) = caps.all {
                return (l, Some(RuleRef::Scope(ri)));
            }
        }
    }
    let cap = ctx.model.root_cap(role, field);
    let src = ctx
        .index
        .root_rules
        .get(field)
        .and_then(|ids| ids.roles.get(role).copied().or(ids.all))
        .map(RuleRef::Root);
    (cap, src)
}

/// The nodes of a walk that hold field rules, nearest first.
pub(crate) fn rule_nodes<'i>(walk: &Walk<'_, 'i>) -> Vec<&'i ScopeIndex> {
    walk.scopes
        .iter()
        .flatten()
        .copied()
        .filter(|s| !s.rules.is_empty())
        .collect()
}

/// Step 5 for one principal: each field's level is the highest over the
/// deciding roles of min(the role's own level from
/// `Model::effective_field_level` at its item level, the closest field
/// rule). Also returns, per field, the rules that lowered it.
pub(crate) fn field_levels(
    ctx: Ctx<'_>,
    rule_nodes: &[&ScopeIndex],
    side: &Side<'_, '_>,
    keys: &[&FieldKey],
) -> Vec<(Level, Vec<RuleRef>)> {
    keys.iter()
        .map(|f| {
            let mut level = Level::None;
            let mut lowered = Vec::new();
            if side.outcome == Outcome::Found {
                for r in &side.roles {
                    let Some((key, _)) = r.role else { continue };
                    let own = ctx.model.effective_field_level(key, f, r.item);
                    let (cap, src) = closest_cap(ctx, rule_nodes, key, f);
                    if cap < own {
                        lowered.extend(src);
                    }
                    level = level.max(own.min(cap));
                }
            }
            (level, lowered)
        })
        .collect()
}

/// `true` if one deciding role allows the action (step 8).
fn role_allows(ctx: Ctx<'_>, r: &RoleEval<'_>, action: &ActionKey, kind: ActionKind<'_>) -> bool {
    let Some((key, role)) = r.role else {
        return false;
    };
    match kind {
        ActionKind::Level(n) => r.item.satisfies(n),
        ActionKind::Custom(_) => ctx.model.allows_custom_at(key, action, r.item),
        ActionKind::Admin => role.holds(action),
    }
}

/// `true` if this principal's deciding roles allow the action: some role
/// allows it on its own (raw grants are never pooled). Admin keys and
/// owner-only custom actions never go to agents or through delegation.
pub(crate) fn side_allows(
    ctx: Ctx<'_>,
    side: &Side<'_, '_>,
    action: &ActionKey,
    kind: ActionKind<'_>,
    delegated: bool,
) -> bool {
    if side.outcome != Outcome::Found || (kind.owner_only() && (delegated || side.is_agent())) {
        return false;
    }
    side.roles.iter().any(|r| role_allows(ctx, r, action, kind))
}

/// What one deciding role needs for the action, before conditions. The
/// `list_filter` side of [`side_allows`]: for every item level `l`,
/// `item >= need` holds exactly when the role allows the action at `l`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Gate {
    /// The role never allows it.
    Never,
    /// The role always allows it: an admin key it holds.
    Always,
    /// The role allows it when its item level after conditions is at least
    /// this.
    Need(Level),
}

pub(crate) fn gate(
    ctx: Ctx<'_>,
    role: Option<(&RoleKey, &Role)>,
    principal: &Principal,
    action: &ActionKey,
    kind: ActionKind<'_>,
    delegated: bool,
) -> Gate {
    let Some((key, r)) = role else {
        return Gate::Never;
    };
    if kind.owner_only() && (delegated || principal.kind() == PrincipalKind::Agent) {
        return Gate::Never;
    }
    match kind {
        ActionKind::Level(n) => Gate::Need(n),
        ActionKind::Admin if r.holds(action) => Gate::Always,
        ActionKind::Admin => Gate::Never,
        ActionKind::Custom(_) => {
            // The lowest level that allows it, if every higher level does
            // too (it does: `allows_custom_at` only asks for a minimum).
            let allows = |l: Level| ctx.model.allows_custom_at(key, action, l);
            match Level::ALL.into_iter().find(|&l| allows(l)) {
                Some(need) if Level::ALL.into_iter().filter(|&l| l >= need).all(allows) => {
                    Gate::Need(need)
                }
                _ => Gate::Never,
            }
        }
    }
}

/// A reason with a detail, cut to fit the 512-character limit.
pub(crate) fn reason(code: ReasonCode, detail: &str) -> Reason {
    let room = Reason::MAX_CHARS.saturating_sub(code.as_str().len() + 2);
    let cut: String = detail.chars().take(room).collect();
    Reason::with_detail(code, &cut).unwrap_or_else(|_| Reason::new(code))
}

/// The binding ids of a side, for details.
fn binding_ids(
    ctx: Ctx<'_>,
    side: &Side<'_, '_>,
    filter: impl Fn(&RoleEval<'_>) -> bool,
) -> String {
    side.roles
        .iter()
        .filter(|r| filter(r))
        .filter_map(|r| ctx.index.bindings.get(r.binding))
        .map(|b| format!("{} ({})", b.id, b.role))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Why this principal is allowed, for `reason`.
pub(crate) fn allow_reason(
    ctx: Ctx<'_>,
    walk: &Walk<'_, '_>,
    side: &Side<'_, '_>,
    action: &ActionKey,
    kind: ActionKind<'_>,
) -> String {
    let at = walk
        .nodes
        .get(side.node)
        .map(ToString::to_string)
        .unwrap_or_default();
    let who = binding_ids(ctx, side, |r| role_allows(ctx, r, action, kind));
    if side.org_owner {
        format!("{} is the org owner: assignment {who}", side.principal)
    } else {
        format!("{} has assignment {who} at {at}", side.principal)
    }
}

/// Why this principal is denied (CONTRACTS.md 6.2), covering several
/// deciding roles, roles that are gone and the mixed case of a grant on one
/// role and the level on another.
pub(crate) fn deny_reason(
    ctx: Ctx<'_>,
    walk: &Walk<'_, '_>,
    side: &Side<'_, '_>,
    action: &ActionKey,
    kind: ActionKind<'_>,
    delegated: bool,
) -> Reason {
    let p = side.principal;
    let at = |i: usize| {
        walk.nodes
            .get(i)
            .map(ToString::to_string)
            .unwrap_or_default()
    };
    match side.outcome {
        Outcome::NoRole => {
            return reason(
                ReasonCode::NoRole,
                &format!("no assignment for {p} on the path"),
            );
        }
        Outcome::Private(i) => {
            return reason(
                ReasonCode::PrivateScope,
                &format!("private scope {} stopped inheritance for {p}", at(i)),
            );
        }
        Outcome::OutsideReach => {
            return reason(
                ReasonCode::OutsideAiReach,
                &format!(
                    "agent {p} is assigned only at the org root; ai_reach is never the whole org"
                ),
            );
        }
        Outcome::Found => {}
    }
    if kind.owner_only() && delegated {
        return reason(
            ReasonCode::AdminOnly,
            &format!("{action} is owner-only and never allowed through delegation"),
        );
    }
    if kind.owner_only() && side.is_agent() {
        return reason(
            ReasonCode::AdminOnly,
            &format!("{action} is owner-only; agents never hold it"),
        );
    }
    let live: Vec<&RoleEval<'_>> = side.roles.iter().filter(|r| r.role.is_some()).collect();
    if live.is_empty() {
        return reason(
            ReasonCode::NoRole,
            &format!(
                "the deciding assignment(s) {} at {} name a role that is gone or may not be given to that subject",
                binding_ids(ctx, side, |_| true),
                at(side.node)
            ),
        );
    }
    let need = match kind {
        ActionKind::Admin => {
            return reason(
                ReasonCode::AdminOnly,
                &format!("no deciding role at {} holds {action}", at(side.node)),
            );
        }
        ActionKind::Level(n) => n,
        ActionKind::Custom(def) => {
            let holders: Vec<&RoleEval<'_>> = live
                .iter()
                .copied()
                .filter(|r| !def.grant || r.role.is_some_and(|(_, role)| role.holds(action)))
                .collect();
            let need = match def.needs {
                ActionRequirement::Level(l) => l,
                ActionRequirement::OwnerOnly => Level::Full,
            };
            if holders.is_empty() {
                return reason(
                    ReasonCode::MissingGrant,
                    &format!(
                        "no deciding role at {} holds the grant {action}",
                        at(side.node)
                    ),
                );
            }
            let mixed = live
                .iter()
                .any(|r| r.item.satisfies(need) && !holders.iter().any(|h| h.binding == r.binding));
            let note = if mixed {
                "; another deciding role has the level but not the grant, and grants are never pooled"
            } else {
                ""
            };
            return low_level(side, &holders, need, &at(side.node), note);
        }
    };
    low_level(side, &live, need, &at(side.node), "")
}

/// `condition_failed` when a condition took the level below `need`, else
/// `level_too_low`.
fn low_level(
    side: &Side<'_, '_>,
    roles: &[&RoleEval<'_>],
    need: Level,
    at: &str,
    note: &str,
) -> Reason {
    let by_condition: Vec<&&RoleEval<'_>> = roles
        .iter()
        .filter(|r| r.base.satisfies(need) && !r.item.satisfies(need))
        .collect();
    if by_condition.is_empty() {
        let best = roles.iter().map(|r| r.item).max().unwrap_or(Level::None);
        reason(
            ReasonCode::LevelTooLow,
            &format!("{} has {best} at {at}, needs {need}{note}", side.principal),
        )
    } else {
        let conds = by_condition
            .iter()
            .flat_map(|r| r.fired.iter())
            .filter_map(|&ci| condition_id(ci))
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        reason(
            ReasonCode::ConditionFailed,
            &format!(
                "{} at {at}: condition(s) {conds} false, so the level is below {need}{note}",
                side.principal
            ),
        )
    }
}
