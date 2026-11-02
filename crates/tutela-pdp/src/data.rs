//! The tenant data the evaluator reads besides the model: role assignments,
//! groups, private scopes and field rules at one scope.
//!
//! These are `tutela-store` data: `tutela_store::load` reads them (ADR-0014).
//! A product may also build [`TenantData`] itself, for example in tests.
//! [`crate::Pdp::load`] checks it and builds an index; it never repairs it.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use tutela_contracts::decision::RuleId;
use tutela_contracts::keys::{FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::OrgId;

use crate::api::PathEntry;
use crate::model::{GroupKey, Model, RoleKey};

/// The most levels of groups inside groups (a group that is in no group is
/// level 1). Deeper nesting is refused when the bundle is loaded
/// (ADR-0013).
pub const MAX_GROUP_DEPTH: usize = 32;

/// The most (principal, group) pairs in the group closure of one tenant:
/// every group each principal is in, directly or through groups. A bigger
/// closure is refused when the bundle is loaded, so one tenant's data cannot
/// make the process allocate without bound (ADR-0013).
pub const MAX_GROUP_CLOSURE: usize = 1_000_000;

/// The most steps to compute the group closure of one tenant: every group
/// copied into a set while each group's and each principal's groups are
/// gathered. Like [`MAX_GROUP_CLOSURE`], it bounds the work one tenant's data
/// can cause (ADR-0013).
pub const MAX_GROUP_WORK: usize = 4 * MAX_GROUP_CLOSURE;

/// Who a role assignment is for.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Subject {
    /// One principal.
    Principal(Principal),
    /// Every member of a group, directly or through groups.
    Group(GroupKey),
}

/// A role assignment: one subject, one role, one scope
/// (PERMISSION-MODEL.md 6.3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Binding {
    /// The stored id, for `rule_ids`.
    pub id: RuleId,
    /// Who.
    pub subject: Subject,
    /// The role. A role the model no longer has still decides its scope and
    /// gives nothing.
    pub role: RoleKey,
    /// Where: any node of a tree, the org root included.
    pub scope: PathEntry,
}

/// A member of a group.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Member {
    /// A principal.
    Principal(Principal),
    /// Every member of another group.
    Group(GroupKey),
}

/// A group (PERMISSION-MODEL.md 6.4). In Phase A, group keys are unique in
/// the tenant (ADR-0013).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Group {
    /// The key that bindings and the `in_group` template name.
    pub key: GroupKey,
    /// The direct members.
    pub members: Vec<Member>,
}

/// A field rule at one scope (PERMISSION-MODEL.md 7.1 step 5). Rules at the
/// org root come from the manifest, not from here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScopeFieldRule {
    /// The stored id, for `rule_ids`.
    pub id: RuleId,
    /// Where. Not an org root.
    pub scope: PathEntry,
    /// The field or feature.
    pub field: FieldKey,
    /// The role, or `None` for all roles.
    pub role: Option<RoleKey>,
    /// The cap.
    pub max: Level,
}

/// Who may move items across a scope's boundary (PERMISSION-MODEL.md 10).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum MoveRule {
    /// Whoever may write in the scope.
    Members,
    /// Whoever holds `approve_move` on the scope.
    Owners,
    /// Nobody.
    Nobody,
}

/// What happens to a move that would give someone more access
/// (PERMISSION-MODEL.md 10).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum OnLooser {
    /// It waits for the source owner's approval.
    Approve,
    /// It is refused.
    Block,
}

/// Where a link into a scope may come from (PERMISSION-MODEL.md 9).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum LinksFrom {
    /// Any scope of the org.
    Any,
    /// Only from under the scope's parent.
    Team,
    /// Only from inside the scope.
    Nobody,
}

/// The move and link rules of one scope. `None` is the default of
/// PERMISSION-MODEL.md 8.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BoundaryRule {
    /// Who may move items out.
    pub moves_out: Option<MoveRule>,
    /// Who may move items in.
    pub moves_in: Option<MoveRule>,
    /// What a move into a looser scope does.
    pub on_looser: Option<OnLooser>,
    /// Where links into this scope may come from.
    pub links_from: Option<LinksFrom>,
}

/// Everything the evaluator reads about one tenant besides the model.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TenantData {
    /// The tenant's orgs. A resource whose path ends at another org belongs
    /// to another tenant: every check on it is denied.
    pub orgs: BTreeSet<OrgId>,
    /// The role assignments. At most one per (subject, scope).
    pub bindings: Vec<Binding>,
    /// The groups.
    pub groups: Vec<Group>,
    /// The private scopes: each one stops inheritance from above. A scope is
    /// private only when it is listed here; `tutela-store` records it when
    /// the scope is made, from its type's `starts`.
    pub private_scopes: BTreeSet<PathEntry>,
    /// The field rules at single scopes.
    pub field_rules: Vec<ScopeFieldRule>,
    /// The move and link rules of single scopes. A scope not listed has the
    /// defaults.
    pub boundaries: BTreeMap<PathEntry, BoundaryRule>,
}

/// Why [`crate::Pdp::load`] refused a bundle.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// The revision is above 2^53 − 1 (the JSON integer range).
    #[error("the revision must be at most 2^53 - 1")]
    RevTooLarge,
    /// The revision is lower than one already loaded for this tenant.
    #[error("revision {got} is lower than revision {have}, which was already loaded")]
    LowerRevision {
        /// The highest revision loaded before.
        have: u64,
        /// The refused revision.
        got: u64,
    },
    /// An `org` scope whose id is not an org of the tenant.
    #[error("scope {0} is not an org of this tenant")]
    UnknownOrg(PathEntry),
    /// Two bindings for the same subject at the same scope.
    #[error("binding {0} repeats a (subject, scope) pair")]
    DuplicateBinding(RuleId),
    /// A binding or a group names a group that does not exist.
    #[error("unknown group `{0}`")]
    UnknownGroup(GroupKey),
    /// Two groups with the same key.
    #[error("group `{0}` is defined twice")]
    DuplicateGroup(GroupKey),
    /// Groups contain each other in a cycle.
    #[error("group `{0}` contains itself through other groups")]
    GroupCycle(GroupKey),
    /// Groups nest deeper than [`MAX_GROUP_DEPTH`].
    #[error("group `{0}` is nested more than 32 levels deep")]
    GroupsTooDeep(GroupKey),
    /// The group closure is bigger than [`MAX_GROUP_CLOSURE`], or takes more
    /// than [`MAX_GROUP_WORK`] steps to compute.
    #[error(
        "the group closure has more than 1,000,000 (principal, group) pairs or takes more than 4,000,000 steps"
    )]
    GroupClosureTooLarge,
    /// An org that another loaded tenant already claims.
    #[error("org `{0}` already belongs to another tenant")]
    OrgClaimed(OrgId),
    /// A field rule at an org root: those come from the manifest.
    #[error("field rule {0} sits at an org root; org-root rules come from the manifest")]
    OrgRootRule(RuleId),
    /// Two field rules for the same (scope, field, role).
    #[error("field rule {0} repeats a (scope, field, role) triple")]
    DuplicateRule(RuleId),
}

/// The caps of the field rules at one scope for one field.
#[derive(Default)]
pub(crate) struct NodeCaps {
    /// The all-roles rule: (cap, rule index).
    pub all: Option<(Level, usize)>,
    /// The rules for one role.
    pub roles: HashMap<RoleKey, (Level, usize)>,
}

/// Everything known about one scope.
#[derive(Default)]
pub(crate) struct ScopeIndex {
    /// Direct bindings by principal.
    pub direct: HashMap<Principal, usize>,
    /// Group bindings: group index → binding index.
    pub groups: BTreeMap<usize, usize>,
    /// `true` if the scope stops inheritance.
    pub private: bool,
    /// The move and link rules here.
    pub boundary: BoundaryRule,
    /// The field rules here.
    pub rules: HashMap<FieldKey, NodeCaps>,
}

/// Where a model's org-root field rule sits in `Model::field_rules`, for
/// `rule_ids`.
#[derive(Default)]
pub(crate) struct RootRuleIds {
    pub all: Option<usize>,
    pub roles: HashMap<RoleKey, usize>,
}

/// The checked and indexed tenant data, plus lookups into the model.
pub(crate) struct Index {
    pub orgs: HashSet<OrgId>,
    pub bindings: Vec<Binding>,
    pub scopes: HashMap<PathEntry, ScopeIndex>,
    /// Direct bindings by principal.
    pub by_principal: HashMap<Principal, Vec<usize>>,
    /// Group bindings by group index.
    pub by_group: Vec<Vec<usize>>,
    pub group_ids: HashMap<GroupKey, usize>,
    /// Every group a principal is in, directly or through groups.
    pub member_of: HashMap<Principal, BTreeSet<usize>>,
    /// The private scopes, sorted.
    pub private: Vec<PathEntry>,
    pub field_rules: Vec<ScopeFieldRule>,
    /// The model's conditions by role and type: indexes into
    /// `Model::conditions`.
    pub conditions: HashMap<RoleKey, HashMap<ResourceType, Vec<usize>>>,
    /// The model's org-root field rules by field.
    pub root_rules: HashMap<FieldKey, RootRuleIds>,
    /// The fields and then the features of each declared type, as keys.
    pub type_fields: HashMap<ResourceType, Vec<FieldKey>>,
}

/// No groups of a principal that is in none.
static NO_GROUPS: BTreeSet<usize> = BTreeSet::new();

impl Index {
    /// Checks the data and builds the index.
    pub fn build(model: &Model, data: TenantData) -> Result<Self, LoadError> {
        let TenantData {
            orgs,
            bindings,
            groups,
            private_scopes,
            field_rules,
            boundaries,
        } = data;
        let orgs: HashSet<OrgId> = orgs.into_iter().collect();
        let check_scope = |scope: &PathEntry| -> Result<(), LoadError> {
            if scope.is_org() && !scope.org_id().is_some_and(|o| orgs.contains(&o)) {
                return Err(LoadError::UnknownOrg(scope.clone()));
            }
            Ok(())
        };

        // Groups and their closure.
        let mut group_ids = HashMap::new();
        for (i, g) in groups.iter().enumerate() {
            if group_ids.insert(g.key.clone(), i).is_some() {
                return Err(LoadError::DuplicateGroup(g.key.clone()));
            }
        }
        // `inside[h]`: the groups that hold group `h` as a member.
        let mut inside: Vec<Vec<usize>> = vec![Vec::new(); groups.len()];
        let mut direct_groups: HashMap<Principal, Vec<usize>> = HashMap::new();
        for (gi, g) in groups.iter().enumerate() {
            for m in &g.members {
                match m {
                    Member::Principal(p) => direct_groups.entry(p.clone()).or_default().push(gi),
                    Member::Group(k) => {
                        let hi = *group_ids
                            .get(k)
                            .ok_or_else(|| LoadError::UnknownGroup(k.clone()))?;
                        if let Some(v) = inside.get_mut(hi) {
                            v.push(gi);
                        }
                    }
                }
            }
        }
        if let Some(g) = find_cycle(&inside).and_then(|gi| groups.get(gi)) {
            return Err(LoadError::GroupCycle(g.key.clone()));
        }
        let order = parents_first(&inside);
        if let Some(g) = too_deep(&inside, &order).and_then(|gi| groups.get(gi)) {
            return Err(LoadError::GroupsTooDeep(g.key.clone()));
        }
        // Each group's own closure once (parents first), then each
        // principal's as the union of its direct groups' closures.
        let mut work = 0usize;
        let mut spend = |n: usize| {
            work = work.saturating_add(n);
            if work > MAX_GROUP_WORK {
                Err(LoadError::GroupClosureTooLarge)
            } else {
                Ok(())
            }
        };
        let mut above: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); inside.len()];
        for &g in &order {
            let mut all = BTreeSet::from([g]);
            for &p in inside.get(g).into_iter().flatten() {
                if let Some(set) = above.get(p) {
                    spend(set.len())?;
                    all.extend(set.iter().copied());
                }
            }
            if let Some(slot) = above.get_mut(g) {
                *slot = all;
            }
        }
        let mut member_of = HashMap::with_capacity(direct_groups.len());
        let mut pairs = 0usize;
        for (p, start) in direct_groups {
            let mut all = BTreeSet::new();
            for g in start {
                if let Some(set) = above.get(g) {
                    spend(set.len())?;
                    all.extend(set.iter().copied());
                }
            }
            pairs = pairs.saturating_add(all.len());
            if pairs > MAX_GROUP_CLOSURE {
                return Err(LoadError::GroupClosureTooLarge);
            }
            member_of.insert(p, all);
        }

        // Bindings.
        let mut scopes: HashMap<PathEntry, ScopeIndex> = HashMap::new();
        let mut by_principal: HashMap<Principal, Vec<usize>> = HashMap::new();
        let mut by_group: Vec<Vec<usize>> = vec![Vec::new(); groups.len()];
        for (bi, b) in bindings.iter().enumerate() {
            check_scope(&b.scope)?;
            let node = scopes.entry(b.scope.clone()).or_default();
            match &b.subject {
                Subject::Principal(p) => {
                    if node.direct.insert(p.clone(), bi).is_some() {
                        return Err(LoadError::DuplicateBinding(b.id.clone()));
                    }
                    by_principal.entry(p.clone()).or_default().push(bi);
                }
                Subject::Group(k) => {
                    let gi = *group_ids
                        .get(k)
                        .ok_or_else(|| LoadError::UnknownGroup(k.clone()))?;
                    if node.groups.insert(gi, bi).is_some() {
                        return Err(LoadError::DuplicateBinding(b.id.clone()));
                    }
                    if let Some(v) = by_group.get_mut(gi) {
                        v.push(bi);
                    }
                }
            }
        }

        // Private scopes.
        for p in &private_scopes {
            check_scope(p)?;
            scopes.entry(p.clone()).or_default().private = true;
        }

        // Move and link rules.
        for (scope, rule) in boundaries {
            check_scope(&scope)?;
            scopes.entry(scope).or_default().boundary = rule;
        }

        // Field rules at single scopes.
        for (ri, r) in field_rules.iter().enumerate() {
            if r.scope.is_org() {
                return Err(LoadError::OrgRootRule(r.id.clone()));
            }
            let caps = scopes
                .entry(r.scope.clone())
                .or_default()
                .rules
                .entry(r.field.clone())
                .or_default();
            let repeated = match &r.role {
                Some(role) => caps.roles.insert(role.clone(), (r.max, ri)).is_some(),
                None => caps.all.replace((r.max, ri)).is_some(),
            };
            if repeated {
                return Err(LoadError::DuplicateRule(r.id.clone()));
            }
        }

        // Lookups into the model.
        let mut conditions: HashMap<RoleKey, HashMap<ResourceType, Vec<usize>>> = HashMap::new();
        for (ci, c) in model.conditions().iter().enumerate() {
            conditions
                .entry(c.role.clone())
                .or_default()
                .entry(c.resource_type.clone())
                .or_default()
                .push(ci);
        }
        let mut root_rules: HashMap<FieldKey, RootRuleIds> = HashMap::new();
        for (ri, r) in model.field_rules().iter().enumerate() {
            let ids = root_rules.entry(r.field.clone()).or_default();
            match &r.role {
                Some(role) => {
                    ids.roles.insert(role.clone(), ri);
                }
                None => ids.all = Some(ri),
            }
        }
        let type_fields = model
            .types()
            .iter()
            .map(|(t, def)| {
                let keys = def
                    .fields
                    .keys()
                    .chain(def.features.iter())
                    .map(|f| FieldKey::new(t.clone(), f.clone()))
                    .collect();
                (t.clone(), keys)
            })
            .collect();

        Ok(Self {
            orgs,
            bindings,
            scopes,
            by_principal,
            by_group,
            group_ids,
            member_of,
            private: private_scopes.into_iter().collect(),
            field_rules,
            conditions,
            root_rules,
            type_fields,
        })
    }

    /// Every group the principal is in.
    pub fn groups_of(&self, p: &Principal) -> &BTreeSet<usize> {
        self.member_of.get(p).unwrap_or(&NO_GROUPS)
    }

    /// The model's conditions on one role and type.
    pub fn conditions_of(&self, role: &RoleKey, t: &ResourceType) -> &[usize] {
        self.conditions
            .get(role)
            .and_then(|m| m.get(t))
            .map_or(&[], Vec::as_slice)
    }

    /// Every binding that applies to the principal somewhere: its direct
    /// bindings and the bindings of every group it is in.
    pub fn bindings_of(&self, p: &Principal) -> Vec<usize> {
        let mut out: Vec<usize> = self.by_principal.get(p).cloned().unwrap_or_default();
        for &gi in self.groups_of(p) {
            out.extend(self.by_group.get(gi).into_iter().flatten().copied());
        }
        out
    }
}

/// A group that reaches itself through `inside`, if any.
fn find_cycle(inside: &[Vec<usize>]) -> Option<usize> {
    // Iterative three-colour depth-first search.
    let mut state = vec![0u8; inside.len()];
    for start in 0..inside.len() {
        if state.get(start).copied() != Some(0) {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        if let Some(s) = state.get_mut(start) {
            *s = 1;
        }
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            let children = inside.get(node).map_or(&[][..], Vec::as_slice);
            if let Some(&child) = children.get(*next) {
                *next += 1;
                match state.get(child).copied() {
                    Some(1) => return Some(child),
                    Some(0) => {
                        if let Some(s) = state.get_mut(child) {
                            *s = 1;
                        }
                        stack.push((child, 0));
                    }
                    _ => {}
                }
            } else {
                if let Some(s) = state.get_mut(node) {
                    *s = 2;
                }
                stack.pop();
            }
        }
    }
    None
}

/// The groups in an order where every group comes after the groups that
/// hold it (Kahn's order). The groups have no cycle.
fn parents_first(inside: &[Vec<usize>]) -> Vec<usize> {
    // `holds[g]`: the groups that `g` holds.
    let mut holds: Vec<Vec<usize>> = vec![Vec::new(); inside.len()];
    let mut parents: Vec<usize> = inside.iter().map(Vec::len).collect();
    for (child, ps) in inside.iter().enumerate() {
        for &p in ps {
            if let Some(v) = holds.get_mut(p) {
                v.push(child);
            }
        }
    }
    let mut todo: Vec<usize> = (0..inside.len())
        .filter(|&g| parents.get(g) == Some(&0))
        .collect();
    let mut order = Vec::with_capacity(inside.len());
    while let Some(g) = todo.pop() {
        order.push(g);
        for &c in holds.get(g).into_iter().flatten() {
            if let Some(n) = parents.get_mut(c) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    todo.push(c);
                }
            }
        }
    }
    order
}

/// A group nested more than [`MAX_GROUP_DEPTH`] levels deep, if any.
fn too_deep(inside: &[Vec<usize>], order: &[usize]) -> Option<usize> {
    let mut depth = vec![1usize; inside.len()];
    for &g in order {
        let d = inside
            .get(g)
            .into_iter()
            .flatten()
            .filter_map(|&p| depth.get(p))
            .max()
            .map_or(1, |d| d + 1);
        if d > MAX_GROUP_DEPTH {
            return Some(g);
        }
        if let Some(slot) = depth.get_mut(g) {
            *slot = d;
        }
    }
    None
}
