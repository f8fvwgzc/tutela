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

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use tutela_contracts::keys::{ActionKey, FieldKey, ResourceType};
use tutela_contracts::level::Level;
use tutela_contracts::principal::Principal;

use crate::api::PathEntry;
use crate::data::ScopeIndex;
use crate::eval::{ActionKind, Ctx, Outcome, Side, action_kind, closest_cap};
use crate::model::{ADMIN_KEYS, Condition, Model, Role, RoleKey};

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
