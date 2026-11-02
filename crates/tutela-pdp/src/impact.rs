//! Who gains or loses what when a resource moves (PERMISSION-MODEL.md 10)
//! or a model changes (15). Both are the same calculation: one principal at
//! one place, before and after.
//!
//! A level is compared per role, with the functions `check` uses. When the
//! field values are not known, which they never are for a resource below the
//! one asked about, a role's conditions could leave its level anywhere from
//! its lowest to its highest. The comparison then errs on the side of saying
//! that someone gains or loses, and marks the line `conditional`. It never
//! says "no change" for a change it could not rule out.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use tutela_contracts::keys::{ActionKey, FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;
use tutela_contracts::tenant::TenantKey;

use crate::api::{PathEntry, PdpError, ScopePaths};
use crate::data::ScopeIndex;
use crate::eval::{
    ActionKind, Ctx, Outcome, Side, Walk, action_kind, closest_cap, resolve_unseen, rule_nodes,
};
use crate::model::{ADMIN_KEYS, Condition, Model, Role, RoleKey};
use crate::pdp::{Bundle, Pdp};

/// One thing a principal can hold on one type.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) enum Access {
    /// The item level on a type.
    Item(ResourceType),
    /// The level on a field or a feature.
    Field(FieldKey),
    /// A custom action or an admin key.
    Action(ActionKey),
}

impl Access {
    /// The action's answer is yes or no. It is kept as `Full` or `None`.
    fn word(&self, l: Level) -> &'static str {
        match self {
            Self::Action(_) if l == Level::None => "denied",
            Self::Action(_) => "allowed",
            _ => l.as_str(),
        }
    }
}

impl core::fmt::Display for Access {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Item(t) => write!(f, "{t}"),
            Self::Field(k) => write!(f, "{k}"),
            Self::Action(k) => write!(f, "{k}"),
        }
    }
}

/// Everything a principal can hold on `t`.
pub(crate) fn keys_of(model: &Model, t: &ResourceType) -> Vec<Access> {
    let mut out = vec![Access::Item(t.clone())];
    if let Some(def) = model.types().get(t) {
        out.extend(
            def.fields
                .keys()
                .chain(def.features.iter())
                .map(|f| Access::Field(FieldKey::new(t.clone(), f.clone()))),
        );
        out.extend(
            def.actions
                .keys()
                .map(|a| Access::Action(ActionKey::new(t.clone(), a.clone()))),
        );
    }
    out.extend(
        ADMIN_KEYS
            .iter()
            .filter_map(|k| ActionKey::parse(&format!("{t}:{k}")).ok())
            .map(Access::Action),
    );
    out
}

/// The types that can sit below `t`, by the model's `parent` rules. `t`
/// itself only when it can hold itself.
pub(crate) fn types_below(model: &Model, t: &ResourceType) -> BTreeSet<ResourceType> {
    let mut out: BTreeSet<ResourceType> = BTreeSet::new();
    let mut todo = vec![t.clone()];
    while let Some(next) = todo.pop() {
        for (child, def) in model.types() {
            if def.parents.contains(&next) && out.insert(child.clone()) {
                todo.push(child.clone());
            }
        }
    }
    out
}

/// One deciding role of a principal at one place.
struct Held<'m> {
    key: &'m RoleKey,
    role: &'m Role,
    /// The highest level its conditions can leave.
    base: Level,
    /// The lowest.
    floor: Level,
    /// Its conditions on the type. Empty when the field values are known:
    /// `base` and `floor` are then the same.
    conditions: Vec<&'m Condition>,
}

/// One principal at one place under one model.
pub(crate) struct Seat<'s, 'm> {
    ctx: Ctx<'m>,
    rules: &'s [&'m ScopeIndex],
    held: Vec<Held<'m>>,
    agent: bool,
}

impl<'s, 'm> Seat<'s, 'm> {
    /// `side` came from [`crate::eval::resolve`]: the field values are known.
    pub fn seen(ctx: Ctx<'m>, rules: &'s [&'m ScopeIndex], side: &Side<'_, 'm>) -> Self {
        let held = found(side)
            .filter_map(|r| {
                let (key, role) = r.role?;
                Some(Held {
                    key,
                    role,
                    base: r.item,
                    floor: r.item,
                    conditions: Vec::new(),
                })
            })
            .collect();
        Self {
            ctx,
            rules,
            held,
            agent: side.is_agent(),
        }
    }

    /// `side` came from [`crate::eval::resolve_unseen`]: every condition
    /// counted as false, so `item` is the lowest it can be.
    pub fn unseen(ctx: Ctx<'m>, rules: &'s [&'m ScopeIndex], side: &Side<'_, 'm>) -> Self {
        let held = found(side)
            .filter_map(|r| {
                let (key, role) = r.role?;
                Some(Held {
                    key,
                    role,
                    base: r.base,
                    floor: r.item,
                    conditions: r
                        .fired
                        .iter()
                        .filter_map(|&ci| ctx.model.conditions().get(ci))
                        .collect(),
                })
            })
            .collect();
        Self {
            ctx,
            rules,
            held,
            agent: side.is_agent(),
        }
    }

    /// What one role gives on `a` at item level `l`, with the same functions
    /// `check` uses.
    fn value(&self, h: &Held<'m>, l: Level, a: &Access) -> Level {
        match a {
            Access::Item(_) => l,
            Access::Field(f) => self
                .ctx
                .model
                .effective_field_level(h.key, f, l)
                .min(closest_cap(self.ctx, self.rules, h.key, f).0),
            Access::Action(k) => {
                let allowed = match action_kind(self.ctx.model, k) {
                    Ok(kind) if kind.owner_only() && self.agent => false,
                    Ok(ActionKind::Admin) => h.role.holds(k),
                    Ok(ActionKind::Custom(_)) => self.ctx.model.allows_custom_at(h.key, k, l),
                    _ => false,
                };
                if allowed { Level::Full } else { Level::None }
            }
        }
    }

    /// The lowest and the highest answer on `a`. Roles combine by taking the
    /// highest, and every level function only goes up with the item level.
    fn range(&self, a: &Access) -> (Level, Level) {
        let at = |l: fn(&Held<'m>) -> Level| {
            self.held
                .iter()
                .map(|h| self.value(h, l(h), a))
                .max()
                .unwrap_or(Level::None)
        };
        (at(|h| h.floor), at(|h| h.base))
    }

    /// `true` when `other` holds the same roles with the same conditions, so
    /// one set of field values fails the same conditions on both sides.
    fn same_conditions(&self, other: &Self) -> bool {
        self.held.len() == other.held.len()
            && self.held.iter().all(|h| {
                other.held.iter().any(|o| {
                    o.key == h.key
                        && o.conditions.len() == h.conditions.len()
                        && o.conditions
                            .iter()
                            .zip(&h.conditions)
                            .all(|(x, y)| x.when == y.when && x.otherwise == y.otherwise)
                })
            })
    }
}

fn found<'a, 'm>(side: &'a Side<'_, 'm>) -> impl Iterator<Item = &'a crate::eval::RoleEval<'m>> {
    side.roles.iter().filter(|_| side.outcome == Outcome::Found)
}

/// Gain or loss.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Someone gets more.
    Gain,
    /// Someone gets less.
    Lose,
}

/// One change for one principal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(crate) struct Delta {
    pub change: Change,
    pub access: Access,
    pub from: Level,
    pub to: Level,
    /// It depends on field values that are not known.
    pub conditional: bool,
}

/// The gain and the loss on `a`, if there can be one.
fn compare_key(before: &Seat<'_, '_>, after: &Seat<'_, '_>, a: &Access, out: &mut Vec<Delta>) {
    let (lo0, hi0) = before.range(a);
    let (lo1, hi1) = after.range(a);
    let mut push = |change, from, to, conditional| {
        out.push(Delta {
            change,
            access: a.clone(),
            from,
            to,
            conditional,
        });
    };
    if lo0 == hi0 && lo1 == hi1 {
        if hi1 > hi0 {
            push(Change::Gain, hi0, hi1, false);
        } else if hi1 < hi0 {
            push(Change::Lose, hi0, hi1, false);
        }
        return;
    }
    let (gain, lose) = if before.same_conditions(after) {
        correlated(before, after, a)
    } else {
        (hi1 > lo0, hi0 > lo1)
    };
    if gain {
        push(Change::Gain, lo0, hi1, true);
    }
    if lose {
        push(Change::Lose, hi0, lo1, true);
    }
}

/// The same roles and conditions on both sides: a row fails the same
/// conditions on both, so each role is compared with itself at each level
/// the failed conditions can leave. A real gain shows on the role that gives
/// it, so this never misses one.
fn correlated(before: &Seat<'_, '_>, after: &Seat<'_, '_>, a: &Access) -> (bool, bool) {
    let (mut gain, mut lose) = (false, false);
    for h0 in &before.held {
        let Some(h1) = after.held.iter().find(|h| h.key == h0.key) else {
            continue;
        };
        let caps = core::iter::once(Level::Full).chain(h0.conditions.iter().map(|c| c.otherwise));
        for cap in caps {
            let v0 = before.value(h0, h0.base.min(cap), a);
            let v1 = after.value(h1, h1.base.min(cap), a);
            gain |= v1 > v0;
            lose |= v0 > v1;
        }
    }
    (gain, lose)
}

/// A count of steps, so one call does a bounded amount of work. A caller
/// that runs out never treats that as "nothing changed".
pub(crate) struct Budget {
    left: usize,
}

impl Budget {
    pub const fn new(steps: usize) -> Self {
        Self { left: steps }
    }

    /// Takes `n` steps. `false` when there are not enough left.
    pub fn take(&mut self, n: usize) -> bool {
        let Some(left) = self.left.checked_sub(n) else {
            return false;
        };
        self.left = left;
        true
    }
}

/// Every change between two seats on `keys`. `None` when the budget ran out.
pub(crate) fn compare(
    before: &Seat<'_, '_>,
    after: &Seat<'_, '_>,
    keys: &[Access],
    budget: &mut Budget,
) -> Option<Vec<Delta>> {
    if !budget.take(keys.len()) {
        return None;
    }
    let mut out = Vec::new();
    for a in keys {
        compare_key(before, after, a, &mut out);
    }
    Some(out)
}

/// One line of an impact report, or of a move's `gains`: "12 users gain read
/// on contract".
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ImpactLine {
    /// Gain or lose.
    pub change: Change,
    /// The principal kind: `user`, `sa`, `key`, `agent` or `workload`.
    pub kind: String,
    /// The type, field, feature or action.
    pub key: String,
    /// The level before, or `denied`.
    pub from: String,
    /// The level after, or `allowed`.
    pub to: String,
    /// `true` when it depends on field values Tutela does not have: it can
    /// happen, and may not happen to every row.
    pub conditional: bool,
    /// Every principal it happens to, sorted.
    pub principals: Vec<String>,
    /// Where, sorted.
    pub scopes: Vec<PathEntry>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LineKey {
    change: Change,
    kind: &'static str,
    access: Access,
    from: Level,
    to: Level,
    conditional: bool,
}

/// Lines being added up.
#[derive(Default)]
pub(crate) struct Tally<'p> {
    lines: BTreeMap<LineKey, (BTreeSet<&'p Principal>, BTreeSet<PathEntry>)>,
}

impl<'p> Tally<'p> {
    pub fn add(&mut self, p: &'p Principal, place: &PathEntry, d: &Delta) {
        let (who, wher) = self
            .lines
            .entry(LineKey {
                change: d.change,
                kind: p.kind().as_str(),
                access: d.access.clone(),
                from: d.from,
                to: d.to,
                conditional: d.conditional,
            })
            .or_default();
        who.insert(p);
        if !wher.contains(place) {
            wher.insert(place.clone());
        }
    }

    pub fn lines(self) -> Vec<ImpactLine> {
        self.lines
            .into_iter()
            .map(|(k, (who, wher))| ImpactLine {
                change: k.change,
                kind: k.kind.to_owned(),
                key: k.access.to_string(),
                from: k.access.word(k.from).to_owned(),
                to: k.access.word(k.to).to_owned(),
                conditional: k.conditional,
                principals: who.into_iter().map(ToString::to_string).collect(),
                scopes: wher.into_iter().collect(),
            })
            .collect()
    }
}

// ---------- The impact of a model change ----------

/// The most steps one report takes, each of one principal at one place or
/// one key compared. It keeps a report under a few seconds. A report that
/// reaches it says so.
pub const MAX_IMPACT_WORK: usize = 2_000_000;

/// What a candidate model would do to one tenant (PERMISSION-MODEL.md 15.1
/// step 3): who gains or loses what, over the tenant's real bindings.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct ImpactReport {
    /// `false` when the report stopped at its bound. Its lines are then a
    /// lower bound, and it says nothing about what it did not reach.
    pub complete: bool,
    /// The changes, sorted.
    pub lines: Vec<ImpactLine>,
}

impl ImpactReport {
    /// `true` only when the whole tenant was looked at and nobody gains or
    /// loses anything. A report that stopped early is never "no impact".
    #[must_use]
    pub fn no_impact(&self) -> bool {
        self.complete && self.lines.is_empty()
    }

    /// One sentence per line: "12 users gain read on contract in 3 scopes".
    #[must_use]
    pub fn summary(&self) -> Vec<String> {
        self.lines.iter().map(ImpactLine::sentence).collect()
    }
}

impl ImpactLine {
    /// The line in plain words.
    #[must_use]
    pub fn sentence(&self) -> String {
        let n = self.principals.len();
        let who = match (self.kind.as_str(), n) {
            ("sa", 1) => "service account".to_owned(),
            ("sa", _) => "service accounts".to_owned(),
            (kind, 1) => kind.to_owned(),
            (kind, _) => format!("{kind}s"),
        };
        let verb = match (self.change, n) {
            (Change::Gain, 1) => "gains",
            (Change::Gain, _) => "gain",
            (Change::Lose, 1) => "loses",
            (Change::Lose, _) => "lose",
        };
        let what = match (self.change, self.to.as_str(), self.from.as_str()) {
            (Change::Gain, "allowed", _) | (Change::Lose, _, "allowed") => self.key.clone(),
            (Change::Gain, to, _) => format!("{to} on {}", self.key),
            (Change::Lose, _, from) => format!("{from} on {}", self.key),
        };
        let m = self.scopes.len();
        let scopes = if m == 1 { "scope" } else { "scopes" };
        let note = if self.conditional {
            ", depending on field values"
        } else {
            ""
        };
        format!("{n} {who} {verb} {what} in {m} {scopes}{note}")
    }
}

/// What differs between two models, so a report looks at nothing else.
struct Changed {
    types: BTreeSet<ResourceType>,
    roles: BTreeSet<RoleKey>,
    every_role: bool,
}

impl Changed {
    fn of(m0: &Model, m1: &Model) -> Self {
        let mut c = Self {
            types: BTreeSet::new(),
            roles: BTreeSet::new(),
            every_role: false,
        };
        let names: BTreeSet<&ResourceType> = m0.types().keys().chain(m1.types().keys()).collect();
        for t in names {
            if m0.types().get(t) != m1.types().get(t) {
                c.types.insert(t.clone());
                c.every_role = true;
            }
        }
        let empty = Role::nothing();
        let keys: BTreeSet<&RoleKey> = m0.roles().keys().chain(m1.roles().keys()).collect();
        for r in keys {
            let (a, b) = (m0.roles().get(r), m1.roles().get(r));
            if a == b {
                continue;
            }
            c.roles.insert(r.clone());
            c.role_types(a.unwrap_or(&empty), b.unwrap_or(&empty));
        }
        for (x, y) in [(m0, m1), (m1, m0)] {
            for k in x.conditions() {
                if !y.conditions().contains(k) {
                    c.roles.insert(k.role.clone());
                    c.types.insert(k.resource_type.clone());
                }
            }
            for rule in x.field_rules() {
                if !y.field_rules().contains(rule) {
                    c.types.insert(rule.field.resource_type().clone());
                    match &rule.role {
                        Some(r) => {
                            c.roles.insert(r.clone());
                        }
                        None => c.every_role = true,
                    }
                }
            }
        }
        c
    }

    /// The types on which one role differs. Who may hold a role changes what
    /// it gives on every type.
    fn role_types(&mut self, a: &Role, b: &Role) {
        let levels = a.levels.keys().chain(b.levels.keys());
        for t in levels {
            if a.level(t) != b.level(t) || a.assignable_to != b.assignable_to {
                self.types.insert(t.clone());
            }
        }
        for (x, y) in [(a, b), (b, a)] {
            for (f, l) in &x.field_levels {
                if y.field_levels.get(f) != Some(l) {
                    self.types.insert(f.resource_type().clone());
                }
            }
            for g in &x.grants {
                if !y.grants.contains(g) {
                    self.types.insert(g.resource_type().clone());
                }
            }
        }
    }

    fn counts(&self, role: &RoleKey) -> bool {
        self.every_role || self.roles.contains(role)
    }
}

/// What a report compares at one place.
struct Place<'r> {
    types: Vec<(&'r ResourceType, &'r [Access])>,
    /// A place of a type that holds nothing by the model can still have rows
    /// below it (ADR-0013 item 1), so every changed type counts there, and
    /// its lines are `conditional`.
    unsure: bool,
}

/// The types a resource at `place` can be, or can hold, in either model.
fn place_types<'r>(
    m0: &Model,
    m1: &Model,
    place: &PathEntry,
    keys: &'r BTreeMap<ResourceType, Vec<Access>>,
) -> Place<'r> {
    let ty = &place.type_name;
    let def = m1.types().get(ty).or_else(|| m0.types().get(ty));
    let unsure = !place.is_org() && def.is_none_or(|d| !d.container);
    let mut below = types_below(m0, ty);
    below.extend(types_below(m1, ty));
    let types = keys
        .iter()
        .filter(|(t, _)| unsure || place.is_org() || *t == ty || below.contains(*t))
        .map(|(t, k)| (t, k.as_slice()))
        .collect();
    Place { types, unsure }
}

/// Every principal who holds a changed role somewhere on `nodes`: only they
/// can see a difference, because the deciding role of anyone else is the same
/// in both models. `members[g]` lists the members of group `g`.
fn holders<'b>(
    b: &'b Bundle,
    nodes: &[&PathEntry],
    changed: &Changed,
    members: &[Vec<&'b Principal>],
) -> BTreeSet<&'b Principal> {
    let counts = |bi: usize| {
        b.index
            .bindings
            .get(bi)
            .is_some_and(|x| changed.counts(&x.role))
    };
    let mut out: BTreeSet<&Principal> = BTreeSet::new();
    for n in nodes {
        let Some(s) = b.index.scopes.get(*n) else {
            continue;
        };
        out.extend(
            s.direct
                .iter()
                .filter(|(_, bi)| counts(**bi))
                .map(|(p, _)| p),
        );
        for (g, bi) in &s.groups {
            if counts(*bi) {
                out.extend(members.get(*g).into_iter().flatten().copied());
            }
        }
    }
    out
}

/// Who gains or loses what between two evaluators of one tenant, with the
/// same data and two models. Neither evaluator changes, and nothing is
/// written. Each place is a scope that holds something: an assignment, a
/// field rule or a private flag, where the answer can differ from its parent.
///
/// `limit` bounds the work ([`MAX_IMPACT_WORK`]). At the bound the report
/// ends with `complete: false`: it never reads as "no impact".
///
/// # Errors
///
/// [`PdpError::NoBundle`] for a tenant that is not loaded, and
/// [`PdpError::ScopePath`] for a scope that cannot be placed.
pub fn model_impact<P: ScopePaths + ?Sized>(
    before: &Pdp,
    after: &Pdp,
    tenant: &TenantKey,
    paths: &P,
    limit: usize,
) -> Result<ImpactReport, PdpError> {
    let b0 = before.bundle(tenant, None)?;
    let b1 = after.bundle(tenant, None)?;
    let (m0, m1) = (&*b0.model, &*b1.model);
    let changed = Changed::of(m0, m1);
    let keys: BTreeMap<ResourceType, Vec<Access>> = changed
        .types
        .iter()
        .map(|t| {
            let mut k: BTreeSet<Access> = keys_of(m0, t).into_iter().collect();
            k.extend(keys_of(m1, t));
            (t.clone(), k.into_iter().collect())
        })
        .collect();
    let mut tally = Tally::default();
    if keys.is_empty() {
        return Ok(ImpactReport {
            complete: true,
            lines: Vec::new(),
        });
    }
    let (ctx0, ctx1) = (b0.ctx(), b1.ctx());
    let mut members: Vec<Vec<&Principal>> = vec![Vec::new(); b0.index.by_group.len()];
    for (p, groups) in &b0.index.member_of {
        for &g in groups {
            if let Some(m) = members.get_mut(g) {
                m.push(p);
            }
        }
    }
    // An org root that holds an assignment is one of these; one that holds
    // none gives nobody anything below it.
    let places: BTreeSet<PathEntry> = b0.index.scopes.keys().cloned().collect();
    let mut budget = Budget::new(limit);
    let mut complete = true;
    'places: for place in &places {
        let path = if place.is_org() {
            Vec::new()
        } else {
            paths
                .ancestors(tenant, place)
                .map_err(|e| crate::search::path_error(place, e))?
        };
        let (w0, w1) = (
            Walk::new(&b0.index, place, &path),
            Walk::new(&b1.index, place, &path),
        );
        let (r0, r1) = (rule_nodes(&w0), rule_nodes(&w1));
        let here = place_types(m0, m1, place, &keys);
        let who = holders(b0, &w0.nodes, &changed, &members);
        // At one place the answer depends on the deciding assignments only:
        // field values are not known here, so a group of thousands costs one
        // comparison.
        let mut seen: HashMap<(Vec<usize>, bool), Vec<Delta>> = HashMap::new();
        for p in who {
            if !budget.take(1) {
                complete = false;
                break 'places;
            }
            let Some((t0, _)) = here.types.first() else {
                continue;
            };
            let side = resolve_unseen(ctx0, &w0, t0, p);
            let key = (
                side.roles.iter().map(|r| r.binding).collect::<Vec<usize>>(),
                side.is_agent(),
            );
            if !seen.contains_key(&key) {
                let mut all = Vec::new();
                for (t, k) in &here.types {
                    let s0 = resolve_unseen(ctx0, &w0, t, p);
                    let s1 = resolve_unseen(ctx1, &w1, t, p);
                    let found = compare(
                        &Seat::unseen(ctx0, &r0, &s0),
                        &Seat::unseen(ctx1, &r1, &s1),
                        k,
                        &mut budget,
                    );
                    let Some(found) = found else {
                        complete = false;
                        break 'places;
                    };
                    all.extend(found);
                }
                if here.unsure {
                    for d in &mut all {
                        d.conditional = true;
                    }
                }
                seen.insert(key.clone(), all);
            }
            for d in seen.get(&key).into_iter().flatten() {
                tally.add(p, place, d);
            }
        }
    }
    Ok(ImpactReport {
        complete,
        lines: tally.lines(),
    })
}
