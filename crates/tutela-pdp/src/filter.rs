//! List filters (CONTRACTS.md 6.6, PERMISSION-MODEL.md 12): `ids_in`,
//! `container_in` and a condition AST, built by the same evaluator code as
//! `check`.
//!
//! The filter has one term per nesting level of the deciding scopes
//! (ADR-0011, "filter shape"): the deciding scopes on one row's path form a
//! chain, so a row's deepest deciding scope is at level `k` exactly when the
//! row is at or under a level-`k` scope and not at or under any
//! level-`k+1` scope.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use tutela_contracts::keys::{ActionKey, FieldName, ResourceId, ResourceType};
use tutela_contracts::principal::{Principal, PrincipalKind};
use tutela_contracts::tenant::TenantKey;

use crate::api::{MAX_PATH, PathEntry, PdpError, ScopePathError, ScopePathProblem, ScopePaths};
use crate::data::Index;
use crate::eval::{
    ActionKind, Ctx, Gate, bindings_at, gate, names_unknown_group, org_owner, role_for,
};
use crate::model::{RoleKey, Template, Value};

/// At most this many condition nodes (CONTRACTS.md 6.6).
pub const MAX_FILTER_NODES: usize = 4096;
/// At most this condition depth.
pub const MAX_FILTER_DEPTH: usize = 32;
/// At most this many entries in `ids_in`.
pub const MAX_IDS_IN: usize = 10_000;
/// At most this many entries in `container_in`.
pub const MAX_CONTAINER_IN: usize = 10_000;
/// At most this many entries in total: `ids_in`, `container_in`, and every
/// `under.scopes`, `id_in.ids` and `in.values` inside the condition. Each
/// one is a bound array element.
pub const MAX_FILTER_ENTRIES: usize = 20_000;

/// A value in a condition: a JSON string, integer or boolean.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(untagged)]
pub enum FilterValue {
    /// A string. Principal values are principal strings.
    String(String),
    /// An integer.
    Integer(i64),
    /// A boolean.
    Boolean(bool),
}

/// One node of the condition AST (CONTRACTS.md 6.6). In JSON every node is an
/// object with an `op`.
///
/// New ops may come with SDK support, so the enum is `#[non_exhaustive]`.
/// An SDK that meets an op it does not know refuses the whole filter: deny,
/// no rows.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FilterExpr {
    /// Always true.
    True,
    /// Never true.
    False,
    /// All are true. Two or more.
    And {
        /// The nodes.
        args: Vec<FilterExpr>,
    },
    /// Any is true. Two or more.
    Or {
        /// The nodes.
        args: Vec<FilterExpr>,
    },
    /// The node is false.
    Not {
        /// The node.
        arg: Box<FilterExpr>,
    },
    /// The row's field equals the value. False on null.
    Eq {
        /// The field.
        attr: FieldName,
        /// The value.
        value: FilterValue,
    },
    /// The field is not null and not equal to the value.
    Ne {
        /// The field.
        attr: FieldName,
        /// The value.
        value: FilterValue,
    },
    /// The field equals one of the values. False on null.
    In {
        /// The field.
        attr: FieldName,
        /// The values, one or more.
        values: Vec<FilterValue>,
    },
    /// The field is an array of strings that holds the value.
    Contains {
        /// The field.
        attr: FieldName,
        /// The value.
        value: String,
    },
    /// The field is null.
    IsNull {
        /// The field.
        attr: FieldName,
    },
    /// The row's id is in the list.
    IdIn {
        /// The ids, one or more.
        ids: Vec<ResourceId>,
    },
    /// One of the scopes is an ancestor of the row, at any depth. A row is
    /// not under itself.
    Under {
        /// The scopes, one or more.
        scopes: Vec<PathEntry>,
    },
}

/// How big a filter is, against the limits of CONTRACTS.md 6.6.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct FilterSize {
    /// Condition nodes.
    pub nodes: usize,
    /// Condition depth (a single node is depth 1).
    pub depth: usize,
    /// Bound array elements: `ids_in`, `container_in` and the lists inside
    /// the condition.
    pub entries: usize,
}

impl FilterExpr {
    /// All of `args`, folded: `true` drops out, `false` wins, nested `and`
    /// is flattened, one argument stands alone.
    pub(crate) fn and(args: Vec<Self>) -> Self {
        let mut out = Vec::new();
        for a in args {
            match a {
                Self::True => {}
                Self::False => return Self::False,
                Self::And { args } => out.extend(args),
                a => out.push(a),
            }
        }
        match out.len() {
            0 => Self::True,
            1 => out.pop().unwrap_or(Self::True),
            _ => Self::And { args: out },
        }
    }

    /// Any of `args`, folded like [`FilterExpr::and`].
    pub(crate) fn or(args: Vec<Self>) -> Self {
        let mut out = Vec::new();
        for a in args {
            match a {
                Self::False => {}
                Self::True => return Self::True,
                Self::Or { args } => out.extend(args),
                a => out.push(a),
            }
        }
        match out.len() {
            0 => Self::False,
            1 => out.pop().unwrap_or(Self::False),
            _ => Self::Or { args: out },
        }
    }

    /// Not `arg`, folded.
    pub(crate) fn not(arg: Self) -> Self {
        match arg {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Not { arg } => *arg,
            a => Self::Not { arg: Box::new(a) },
        }
    }

    /// The size of this node and everything below it.
    #[must_use]
    pub fn size(&self) -> FilterSize {
        let mut size = FilterSize {
            nodes: 1,
            depth: 1,
            entries: 0,
        };
        let mut add = |child: FilterSize| {
            size.nodes += child.nodes;
            size.depth = size.depth.max(child.depth + 1);
            size.entries += child.entries;
        };
        match self {
            Self::And { args } | Self::Or { args } => args.iter().for_each(|a| add(a.size())),
            Self::Not { arg } => add(arg.size()),
            Self::In { values, .. } => size.entries = values.len(),
            Self::IdIn { ids } => size.entries = ids.len(),
            Self::Under { scopes } => size.entries = scopes.len(),
            Self::True
            | Self::False
            | Self::Eq { .. }
            | Self::Ne { .. }
            | Self::Contains { .. }
            | Self::IsNull { .. } => {}
        }
        size
    }
}

/// A filter to list rows of one type inside SQL (CONTRACTS.md 6.6).
///
/// A row of the listed type and of `tenant` passes if and only if it has at
/// most 32 ancestors and
/// `(row.id is in ids_in OR row is under a scope in container_in) AND
/// condition(row)`. Empty `ids_in` and `container_in` mean no rows.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ListFilter {
    /// The tenant the rows must belong to: the SQL adapter binds it as the
    /// tenant predicate.
    pub tenant: TenantKey,
    /// The listed type.
    #[serde(rename = "type")]
    pub type_name: ResourceType,
    /// The tenant revision that was used.
    pub rev: u64,
    /// Rows allowed by an assignment on the row itself.
    pub ids_in: Vec<ResourceId>,
    /// Scopes; rows anywhere below them match.
    pub container_in: Vec<PathEntry>,
    /// The AST; `None` means true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<FilterExpr>,
}

impl ListFilter {
    fn nothing(tenant: TenantKey, type_name: ResourceType, rev: u64) -> Self {
        Self {
            tenant,
            type_name,
            rev,
            ids_in: Vec::new(),
            container_in: Vec::new(),
            condition: None,
        }
    }

    /// `true` if the filter can match no row.
    #[must_use]
    pub fn matches_nothing(&self) -> bool {
        (self.ids_in.is_empty() && self.container_in.is_empty())
            || self.condition == Some(FilterExpr::False)
    }

    /// The size, against the limits of CONTRACTS.md 6.6.
    #[must_use]
    pub fn size(&self) -> FilterSize {
        let cond = self
            .condition
            .as_ref()
            .map(FilterExpr::size)
            .unwrap_or_default();
        FilterSize {
            entries: cond.entries + self.ids_in.len() + self.container_in.len(),
            ..cond
        }
    }

    pub(crate) fn check_limits(&self) -> Result<(), PdpError> {
        let size = self.size();
        if self.ids_in.len() > MAX_IDS_IN {
            return Err(PdpError::FilterTooLarge("ids_in"));
        }
        if self.container_in.len() > MAX_CONTAINER_IN {
            return Err(PdpError::FilterTooLarge("container_in"));
        }
        if size.nodes > MAX_FILTER_NODES {
            return Err(PdpError::FilterTooLarge("condition nodes"));
        }
        if size.depth > MAX_FILTER_DEPTH {
            return Err(PdpError::FilterTooLarge("condition depth"));
        }
        if size.entries > MAX_FILTER_ENTRIES {
            return Err(PdpError::FilterTooLarge("total entries"));
        }
        Ok(())
    }
}

/// The rows one principal may see.
struct Parts {
    ids_in: BTreeSet<ResourceId>,
    container_in: BTreeSet<PathEntry>,
    condition: Option<FilterExpr>,
}

impl Parts {
    /// Both must pass (the delegation overlap).
    fn and(self, other: Self) -> Self {
        let pos = FilterExpr::or(vec![
            id_in(other.ids_in.into_iter().collect()),
            under(other.container_in.into_iter().collect()),
        ]);
        let condition = FilterExpr::and(
            self.condition
                .into_iter()
                .chain([pos])
                .chain(other.condition)
                .collect(),
        );
        Self {
            ids_in: self.ids_in,
            container_in: self.container_in,
            condition: Some(condition),
        }
    }
}

fn id_in(ids: Vec<ResourceId>) -> FilterExpr {
    if ids.is_empty() {
        FilterExpr::False
    } else {
        FilterExpr::IdIn { ids }
    }
}

fn under(scopes: Vec<PathEntry>) -> FilterExpr {
    if scopes.is_empty() {
        FilterExpr::False
    } else {
        FilterExpr::Under { scopes }
    }
}

/// "The row is one of these scopes, or under one of them."
///
/// `under` is kept for every scope, whatever its type's `container` flag:
/// `check` does not read the flag, and a stored path may run through a type
/// that is no longer a container. Pruning here would drop an exclusion and
/// list rows that `check` denies.
fn at_or_under(listed: &ResourceType, scopes: &[&PathEntry]) -> FilterExpr {
    FilterExpr::or(vec![
        id_in(
            scopes
                .iter()
                .filter(|s| s.type_name == *listed)
                .map(|s| s.id.clone())
                .collect(),
        ),
        under(scopes.iter().map(|&s| s.clone()).collect()),
    ])
}

/// The paths of the scopes a filter needs, from the provider, checked.
/// Each scope is asked for at most once per `list_filter` call.
struct Placer<'a, P: ?Sized> {
    provider: &'a P,
    tenant: &'a TenantKey,
    index: &'a Index,
    cache: BTreeMap<PathEntry, Vec<PathEntry>>,
}

impl<P: ScopePaths + ?Sized> Placer<'_, P> {
    fn place(&mut self, scope: &PathEntry) -> Result<(), PdpError> {
        if scope.is_org() || self.cache.contains_key(scope) {
            return Ok(());
        }
        let fail = |problem| PdpError::ScopePath {
            scope: scope.clone(),
            problem,
        };
        let path = self.provider.ancestors(self.tenant, scope).map_err(|e| {
            fail(match e {
                ScopePathError::NotFound => ScopePathProblem::NotFound,
                _ => ScopePathProblem::Unavailable,
            })
        })?;
        if path.len() > MAX_PATH {
            return Err(fail(ScopePathProblem::TooLong));
        }
        let Some((last, rest)) = path.split_last() else {
            return Err(fail(ScopePathProblem::Malformed));
        };
        if !last.is_org() || rest.iter().any(PathEntry::is_org) {
            return Err(fail(ScopePathProblem::Malformed));
        }
        // The scope itself, or any entry twice, is never on its own path.
        let mut seen = BTreeSet::from([scope]);
        if !path.iter().all(|e| seen.insert(e)) {
            return Err(fail(ScopePathProblem::Malformed));
        }
        if !last.org_id().is_some_and(|o| self.index.orgs.contains(&o)) {
            return Err(fail(ScopePathProblem::WrongTenant));
        }
        self.cache.insert(scope.clone(), path);
        Ok(())
    }

    /// Checks that the placed paths agree: every entry of every placed path
    /// (the scope itself included) has one parent. Two paths that give one
    /// entry two parents disagree, also when that entry was never placed
    /// itself; this also refuses a cycle.
    fn check_consistent(&self) -> Result<(), PdpError> {
        let mut parent: BTreeMap<&PathEntry, &PathEntry> = BTreeMap::new();
        for (scope, path) in &self.cache {
            for (child, up) in core::iter::once(scope).chain(path).zip(path) {
                if *parent.entry(child).or_insert(up) != up {
                    return Err(PdpError::ScopePath {
                        scope: scope.clone(),
                        problem: ScopePathProblem::Inconsistent,
                    });
                }
            }
        }
        Ok(())
    }

    /// The ancestors of a placed scope; empty for an org. An unplaced scope
    /// is an error, never "no ancestors".
    fn ancestors(&self, scope: &PathEntry) -> Result<&[PathEntry], PdpError> {
        if scope.is_org() {
            return Ok(&[]);
        }
        self.cache
            .get(scope)
            .map(Vec::as_slice)
            .ok_or_else(|| PdpError::ScopePath {
                scope: scope.clone(),
                problem: ScopePathProblem::NotFound,
            })
    }

    /// The org of a placed scope.
    fn org_of<'s>(&'s self, scope: &'s PathEntry) -> Result<&'s PathEntry, PdpError> {
        Ok(self.ancestors(scope)?.last().unwrap_or(scope))
    }
}

/// The request, resolved once.
pub(crate) struct Listing<'a> {
    pub ctx: Ctx<'a>,
    pub tenant: &'a TenantKey,
    pub action: &'a ActionKey,
    pub kind: ActionKind<'a>,
    pub delegated: bool,
    pub rev: u64,
}

/// Builds the list filter for the subject and every actor, joined with AND.
pub(crate) fn list_filter<P: ScopePaths + ?Sized>(
    l: &Listing<'_>,
    subject: &Principal,
    actors: &[Principal],
    provider: &P,
) -> Result<ListFilter, PdpError> {
    let listed = l.action.resource_type().clone();
    if l.kind.owner_only() && l.delegated {
        return Ok(ListFilter::nothing(l.tenant.clone(), listed, l.rev));
    }
    let mut placer = Placer {
        provider,
        tenant: l.tenant,
        index: l.ctx.index,
        cache: BTreeMap::new(),
    };
    let mut parts: Option<Parts> = None;
    for p in core::iter::once(subject).chain(actors) {
        let Some(side) = side_parts(l, &listed, p, &mut placer)? else {
            return Ok(ListFilter::nothing(l.tenant.clone(), listed, l.rev));
        };
        parts = Some(match parts {
            None => side,
            Some(acc) => acc.and(side),
        });
    }
    let Some(parts) = parts else {
        return Ok(ListFilter::nothing(l.tenant.clone(), listed, l.rev));
    };
    let filter = ListFilter {
        tenant: l.tenant.clone(),
        type_name: listed,
        rev: l.rev,
        ids_in: parts.ids_in.into_iter().collect(),
        container_in: parts.container_in.into_iter().collect(),
        condition: parts.condition,
    };
    filter.check_limits()?;
    if filter.matches_nothing() {
        return Ok(ListFilter::nothing(
            filter.tenant,
            filter.type_name,
            filter.rev,
        ));
    }
    Ok(filter)
}

/// The rows one principal alone may see; `None` for no rows.
fn side_parts<P: ScopePaths + ?Sized>(
    l: &Listing<'_>,
    listed: &ResourceType,
    p: &Principal,
    placer: &mut Placer<'_, P>,
) -> Result<Option<Parts>, PdpError> {
    let Listing { ctx, .. } = *l;
    let index = ctx.index;
    let bindings = index.bindings_of(p);
    if bindings.is_empty() {
        return Ok(None);
    }
    // 1. Every scope where the principal has an assignment, placed.
    let scopes: BTreeSet<&PathEntry> = bindings
        .iter()
        .filter_map(|&b| index.bindings.get(b))
        .map(|b| &b.scope)
        .collect();
    if scopes.len() > MAX_FILTER_ENTRIES {
        return Err(PdpError::FilterTooLarge("total entries"));
    }
    for s in &scopes {
        placer.place(s)?;
    }
    // 2. The private scopes: they stop inheritance from above.
    for x in &index.private {
        placer.place(x)?;
    }
    placer.check_consistent()?;
    let placer = &*placer;

    // 3. The deciding scopes, as `check` finds them: in an org where the
    //    principal is the org Owner, only the org root; elsewhere every
    //    assigned scope with its deciding bindings, and every private scope
    //    with an assigned scope above it.
    let owner_orgs: BTreeMap<&PathEntry, usize> = scopes
        .iter()
        .filter(|s| s.is_org())
        .filter_map(|&s| org_owner(ctx, s, p).map(|b| (s, b)))
        .collect();
    let mut assigned: BTreeMap<&PathEntry, Vec<usize>> =
        owner_orgs.iter().map(|(&org, &b)| (org, vec![b])).collect();
    for &s in &scopes {
        if owner_orgs.contains_key(placer.org_of(s)?) {
            continue;
        }
        if let Some(node) = index.scopes.get(s) {
            let b = bindings_at(index, node, p);
            if !b.is_empty() {
                assigned.insert(s, b);
            }
        }
    }
    let mut deciding: BTreeSet<&PathEntry> = assigned.keys().copied().collect();
    for x in &index.private {
        if assigned.contains_key(x) || owner_orgs.contains_key(placer.org_of(x)?) {
            continue;
        }
        if placer
            .ancestors(x)?
            .iter()
            .any(|a| assigned.contains_key(a))
        {
            deciding.insert(x);
        }
    }

    // 4. The nesting level of each deciding scope: how many deciding scopes
    //    sit above it. The paths are checked, so this is its place in the
    //    chain of deciding scopes on any row's path.
    let mut level: BTreeMap<&PathEntry, usize> = BTreeMap::new();
    let mut by_level: BTreeMap<usize, Vec<&PathEntry>> = BTreeMap::new();
    for &d in &deciding {
        let k = placer
            .ancestors(d)?
            .iter()
            .filter(|a| deciding.contains(a))
            .count();
        level.insert(d, k);
        by_level.entry(k).or_default().push(d);
    }
    let level_of = |d: &PathEntry| level.get(d).copied().unwrap_or(0);

    // 5. Per level: the scopes where some deciding role allows the action
    //    whatever the row, and per role with conditions, the scopes where
    //    it allows it when its conditions hold.
    let p_text = p.to_string();
    let groups = index.groups_of(p);
    let mut terms: BTreeMap<usize, LevelTerms<'_>> = BTreeMap::new();
    for (&d, bs) in &assigned {
        if p.kind() == PrincipalKind::Agent && d.is_org() {
            continue; // `ai_reach` is never the whole org
        }
        let mut always = false;
        let mut conditional: Vec<(&RoleKey, FilterExpr)> = Vec::new();
        for &bi in bs {
            let role = index.bindings.get(bi).and_then(|b| role_for(ctx.model, b));
            let Some((key, r)) = role else { continue };
            match gate(ctx, role, p, l.action, l.kind, l.delegated) {
                Gate::Never => {}
                Gate::Always => always = true,
                Gate::Need(need) => {
                    if !r.level(listed).satisfies(need) {
                        continue;
                    }
                    // The role allows a row when every condition that would
                    // drop it below `need` holds there.
                    let mut parts = Vec::new();
                    for &ci in index.conditions_of(key, listed) {
                        let Some(c) = ctx.model.conditions().get(ci) else {
                            parts.push(FilterExpr::False);
                            continue;
                        };
                        if c.otherwise.satisfies(need) {
                            continue;
                        }
                        if names_unknown_group(index, &c.when) {
                            parts.push(FilterExpr::False);
                        } else {
                            parts.push(compile(index, &c.when, &p_text, groups));
                        }
                    }
                    match FilterExpr::and(parts) {
                        FilterExpr::True => always = true,
                        FilterExpr::False => {}
                        e => conditional.push((key, e)),
                    }
                }
            }
        }
        let t = terms.entry(level_of(d)).or_default();
        if always {
            t.always.push(d);
        } else {
            for (key, e) in conditional {
                t.by_role
                    .entry(key)
                    .or_insert_with(|| (Vec::new(), e))
                    .0
                    .push(d);
            }
        }
    }

    // 6. One term per level.
    let mut ids_in = BTreeSet::new();
    let mut container_in = BTreeSet::new();
    let mut pure = true;
    let mut ors = Vec::new();
    for (k, t) in terms {
        let mut alts = Vec::new();
        let mut allowed: Vec<&PathEntry> = t.always.clone();
        if !t.always.is_empty() {
            alts.push(at_or_under(listed, &t.always));
        }
        for (scopes, e) in t.by_role.into_values() {
            pure = false;
            alts.push(FilterExpr::and(vec![at_or_under(listed, &scopes), e]));
            allowed.extend(scopes);
        }
        if allowed.is_empty() {
            continue;
        }
        for s in allowed {
            if s.type_name == *listed {
                ids_in.insert(s.id.clone());
            }
            container_in.insert(s.clone());
        }
        let mut parts = vec![FilterExpr::or(alts)];
        if let Some(next) = by_level.get(&(k + 1)) {
            pure = false;
            parts.push(FilterExpr::not(at_or_under(listed, next)));
        }
        ors.push(FilterExpr::and(parts));
    }
    if ids_in.is_empty() && container_in.is_empty() {
        return Ok(None);
    }
    Ok(Some(Parts {
        ids_in,
        container_in,
        condition: (!pure).then(|| FilterExpr::or(ors)),
    }))
}

/// The terms of one nesting level.
#[derive(Default)]
struct LevelTerms<'a> {
    /// Scopes where some role allows the action whatever the row.
    always: Vec<&'a PathEntry>,
    /// Per role with conditions: its scopes and its conditions.
    by_role: BTreeMap<&'a RoleKey, (Vec<&'a PathEntry>, FilterExpr)>,
}

/// A condition template as a filter node, with the principal's values
/// filled in. The caller has checked that it names no unknown group.
fn compile(index: &Index, t: &Template, p_text: &str, groups: &BTreeSet<usize>) -> FilterExpr {
    let value = |v: &Value| match v {
        Value::String(s) => FilterValue::String(s.clone()),
        Value::Integer(i) => FilterValue::Integer(*i),
        Value::Boolean(b) => FilterValue::Boolean(*b),
    };
    match t {
        Template::Eq { field, value: v } => FilterExpr::Eq {
            attr: field.clone(),
            value: value(v),
        },
        Template::In { field, values } => FilterExpr::In {
            attr: field.clone(),
            values: values.iter().map(value).collect(),
        },
        Template::Contains { field, value } => FilterExpr::Contains {
            attr: field.clone(),
            value: value.clone(),
        },
        Template::IsPrincipal { field } => FilterExpr::Eq {
            attr: field.clone(),
            value: FilterValue::String(p_text.to_owned()),
        },
        Template::InGroup { group } => {
            if index
                .group_ids
                .get(group)
                .is_some_and(|g| groups.contains(g))
            {
                FilterExpr::True
            } else {
                FilterExpr::False
            }
        }
        Template::And(v) => FilterExpr::and(
            v.iter()
                .map(|x| compile(index, x, p_text, groups))
                .collect(),
        ),
        Template::Or(v) => FilterExpr::or(
            v.iter()
                .map(|x| compile(index, x, p_text, groups))
                .collect(),
        ),
        Template::Not(x) => FilterExpr::not(compile(index, x, p_text, groups)),
    }
}
